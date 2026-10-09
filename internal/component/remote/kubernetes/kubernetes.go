// Package kubernetes implements the logic for remote.kubernetes.secret and remote.kubernetes.configmap component.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	client_go "k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/component/common/kubernetes"
	"github.com/grafana/alloy/syntax/alloytypes"
)

type ResourceType string

const (
	TypeSecret    ResourceType = "secret"
	TypeConfigMap ResourceType = "configmap"
)

// groupResource returns the Kubernetes GroupResource addressed by the
// component, used to build API-equivalent errors for missing resources.
func (t ResourceType) groupResource() schema.GroupResource {
	switch t {
	case TypeSecret:
		return schema.GroupResource{Resource: "secrets"}
	case TypeConfigMap:
		return schema.GroupResource{Resource: "configmaps"}
	}
	return schema.GroupResource{Resource: string(t)}
}

// Arguments control the component.
type Arguments struct {
	Namespace     string        `alloy:"namespace,attr"`
	Name          string        `alloy:"name,attr"`
	PollFrequency time.Duration `alloy:"poll_frequency,attr,optional"`
	PollTimeout   time.Duration `alloy:"poll_timeout,attr,optional"`

	// Client settings to connect to Kubernetes.
	Client kubernetes.ClientArguments `alloy:"client,block,optional"`
}

// DefaultArguments holds default settings for Arguments.
var DefaultArguments = Arguments{
	PollFrequency: 1 * time.Minute,
	PollTimeout:   15 * time.Second,
}

// SetToDefault implements syntax.Defaulter.
func (args *Arguments) SetToDefault() {
	*args = DefaultArguments
}

// Validate implements syntax.Validator.
func (args *Arguments) Validate() error {
	if args.PollFrequency <= 0 {
		return fmt.Errorf("poll_frequency must be greater than 0")
	}
	if args.PollTimeout <= 0 {
		return fmt.Errorf("poll_timeout must not be greater than 0")
	}
	return nil
}

// Exports holds settings exported by this component.
type Exports struct {
	Data map[string]alloytypes.OptionalSecret `alloy:"data,attr"`
}

// coreV1Client is the subset of the Kubernetes CoreV1 API used by the
// component. It is implemented by both the real clientset and the fake
// clientset used in tests.
type coreV1Client interface {
	Secrets(namespace string) corev1client.SecretInterface
	ConfigMaps(namespace string) corev1client.ConfigMapInterface
}

// resourceEventType describes the kind of observation read from the
// Kubernetes API.
type resourceEventType int

const (
	resourceUpdated resourceEventType = iota
	resourceDeleted
)

// resourceEvent is a single observation of the tracked resource: either its
// current contents with their resource version, or its deletion. Exactly
// one of secret or configMap is populated for resourceUpdated events.
type resourceEvent struct {
	eventType       resourceEventType
	resourceVersion string
	secret          *corev1.Secret
	configMap       *corev1.ConfigMap
}

// errStaleResourceVersion is returned when an observation carries a
// resource version which is not newer than the version whose contents are
// already applied. Such observations are ignored: neither the exported
// state nor the component health changes.
var errStaleResourceVersion = errors.New("ignored resource with an older resource version")

// Component implements the remote.kubernetes.* component.
type Component struct {
	opts component.Options

	mut  sync.Mutex
	args Arguments

	client coreV1Client
	kind   ResourceType

	lastPoll    time.Time
	lastExports Exports // Currently applied exports.
	// synced is true once the resource has been read and applied at least
	// once. A NotFound before the first successful sync is a read error
	// (preserving startup behavior); after a sync it is a delete event.
	synced bool
	// lastResourceVersion is the resource version of the currently applied
	// contents. It is empty until the first successful synchronization and
	// acts as the high-water mark which older observations must not cross.
	lastResourceVersion string
	// lastPollStatus is the health message for the last successfully applied
	// observation.
	lastPollStatus string

	healthMut sync.RWMutex
	health    component.Health
}

var (
	_ component.Component       = (*Component)(nil)
	_ component.HealthComponent = (*Component)(nil)
)

// New returns a new, unstarted remote.kubernetes.* component.
func New(opts component.Options, args Arguments, rType ResourceType) (*Component, error) {
	c := &Component{
		opts: opts,
		kind: rType,
		health: component.Health{
			Health:     component.HealthTypeUnknown,
			Message:    "component started",
			UpdateTime: time.Now(),
		},
	}

	if err := c.Update(args); err != nil {
		return nil, err
	}
	return c, nil
}

// Run starts the remote.kubernetes.* component.
func (c *Component) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(c.nextPoll()):
			c.poll()
		}
	}
}

// nextPoll returns how long to wait to poll given the last time a
// poll occurred. nextPoll returns 0 if a poll should occur immediately.
func (c *Component) nextPoll() time.Duration {
	c.mut.Lock()
	defer c.mut.Unlock()

	nextPoll := c.lastPoll.Add(c.args.PollFrequency)
	now := time.Now()

	if now.After(nextPoll) {
		// Poll immediately; next poll period was in the past.
		return 0
	}
	return nextPoll.Sub(now)
}

// poll performs a read of the component's configured resource. c.mut must
// not be held when calling. After polling, the component's health is updated
// with the success or failure status.
func (c *Component) poll() {
	// Run only consumes the poll result through health; the returned error
	// exists for callers (such as Update) which must propagate it.
	_ = c.finishPoll(c.pollError())
}

// finishPoll reports the result of a poll and returns the error which should
// be propagated to the poll's caller. Observations carrying an older
// resource version are ignored and leave both exports and health untouched.
func (c *Component) finishPoll(pollErr error) error {
	if errors.Is(pollErr, errStaleResourceVersion) {
		return nil
	}
	c.updatePollHealth(pollErr)
	return pollErr
}

func (c *Component) updatePollHealth(err error) {
	c.healthMut.Lock()
	defer c.healthMut.Unlock()

	if err == nil {
		c.mut.Lock()
		message := c.lastPollStatus
		c.mut.Unlock()
		if message == "" {
			message = "got " + string(c.kind)
		}
		c.health = component.Health{
			Health:     component.HealthTypeHealthy,
			Message:    message,
			UpdateTime: time.Now(),
		}
	} else {
		c.health = component.Health{
			Health:     component.HealthTypeUnhealthy,
			Message:    fmt.Sprintf("polling failed: %s", err),
			UpdateTime: time.Now(),
		}
	}
}

// pollError is like poll but returns an error if one occurred.
func (c *Component) pollError() error {
	c.mut.Lock()
	defer c.mut.Unlock()

	c.lastPoll = time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), c.args.PollTimeout)
	defer cancel()

	// Read: fetch the observation from the Kubernetes API. A missing
	// resource is normalized into a delete event; transport and API errors
	// are returned directly.
	event, err := c.readResource(ctx)
	if err != nil {
		return err
	}

	// A missing resource before the first successful synchronization keeps
	// the original read-error behavior (including failing startup); only a
	// delete observed after a successful sync clears the component.
	if event.eventType == resourceDeleted && !c.synced {
		return apierrors.NewNotFound(c.kind.groupResource(), c.args.Name)
	}

	// Version check, parse and apply happen atomically so an older or
	// invalid observation can never replace the currently applied contents.
	return c.applyEvent(event)
}

// readResource reads the tracked resource and normalizes it into a
// resourceEvent. A successful read yields a resourceUpdated event carrying
// the object's resource version; a NotFound response yields a
// resourceDeleted event.
//
// The Kubernetes API does not report the deleted object's resource version
// on a NotFound response, so delete events produced here carry no version
// and are treated as the API server's authoritative current state.
func (c *Component) readResource(ctx context.Context) (resourceEvent, error) {
	switch c.kind {
	case TypeSecret:
		secret, err := c.client.Secrets(c.args.Namespace).Get(ctx, c.args.Name, v1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return resourceEvent{eventType: resourceDeleted}, nil
			}
			return resourceEvent{}, err
		}
		return resourceEvent{
			eventType:       resourceUpdated,
			resourceVersion: secret.ResourceVersion,
			secret:          secret,
		}, nil
	case TypeConfigMap:
		cmap, err := c.client.ConfigMaps(c.args.Namespace).Get(ctx, c.args.Name, v1.GetOptions{})
		if err != nil {
			if apierrors.IsNotFound(err) {
				return resourceEvent{eventType: resourceDeleted}, nil
			}
			return resourceEvent{}, err
		}
		return resourceEvent{
			eventType:       resourceUpdated,
			resourceVersion: cmap.ResourceVersion,
			configMap:       cmap,
		}, nil
	}
	return resourceEvent{}, fmt.Errorf("unknown resource type %q", c.kind)
}

// applyEvent processes one observation in resource-version order. c.mut
// must be held by the caller.
//
//   - Observations which are not newer than the applied version are ignored
//     (errStaleResourceVersion), including delete notifications for versions
//     which have already been superseded by a newer read.
//   - For newer observations the contents are parsed first; the new version
//     replaces the current exports only after parsing and applying succeed.
//   - Parse or apply failures leave the previously applied exports in
//     effect and return the error so it can be reported through health.
//   - Deletes clear the exports only when no newer version has already been
//     applied.
//
// The first synchronization (no applied version yet) always accepts the
// observation returned by the API.
func (c *Component) applyEvent(event resourceEvent) error {
	switch event.eventType {
	case resourceDeleted:
		// A versioned delete is stale when a version at least as new as the
		// deleted one is already applied. An unversioned delete (a poll that
		// returned NotFound) is authoritative and is always applied.
		if event.resourceVersion != "" && c.lastResourceVersion != "" {
			cmp, err := compareResourceVersion(event.resourceVersion, c.lastResourceVersion)
			if err == nil && cmp <= 0 {
				return errStaleResourceVersion
			}
		}

		empty := Exports{Data: map[string]alloytypes.OptionalSecret{}}
		if !reflect.DeepEqual(empty.Data, c.lastExports.Data) {
			c.opts.OnStateChange(empty)
		}
		c.lastExports = empty
		// Keep the version high-water mark for versioned deletes so that a
		// delayed update of the deleted version cannot resurrect the
		// contents.
		if event.resourceVersion != "" {
			c.lastResourceVersion = event.resourceVersion
		}
		c.lastPollStatus = string(c.kind) + " deleted"
		return nil

	case resourceUpdated:
		// Version judgment. The watermark is empty on the first
		// synchronization after startup, which must always be accepted.
		if c.lastResourceVersion != "" && event.resourceVersion != "" {
			cmp, err := compareResourceVersion(event.resourceVersion, c.lastResourceVersion)
			if err == nil && cmp <= 0 {
				return errStaleResourceVersion
			}
		}

		// Parse. A failure must leave the current exports untouched.
		newExports, err := c.parseEvent(event)
		if err != nil {
			return err
		}

		// Apply. Only a state change is announced; commit the version only
		// after the new contents have been applied, so an apply failure
		// keeps the previous version live.
		if !reflect.DeepEqual(newExports.Data, c.lastExports.Data) {
			c.opts.OnStateChange(newExports)
		}
		c.lastExports = newExports
		c.lastResourceVersion = event.resourceVersion
		c.lastPollStatus = "got " + string(c.kind)
		c.synced = true
		return nil
	}

	return fmt.Errorf("unknown resource event type %d", event.eventType)
}

// parseEvent converts the object carried by an update observation into
// component exports. It neither reads nor mutates component state.
func (c *Component) parseEvent(event resourceEvent) (Exports, error) {
	data := map[string]alloytypes.OptionalSecret{}

	switch {
	case event.secret != nil:
		for k, v := range event.secret.Data {
			data[k] = alloytypes.OptionalSecret{
				Value:    string(v),
				IsSecret: true,
			}
		}
	case event.configMap != nil:
		for k, v := range event.configMap.Data {
			data[k] = alloytypes.OptionalSecret{
				Value:    v,
				IsSecret: false,
			}
		}
	default:
		return Exports{}, fmt.Errorf("update event for %s %q did not contain an object", c.kind, c.args.Name)
	}

	return Exports{Data: data}, nil
}

// compareResourceVersion reports whether resource version a is older than
// (-1), equal to (0) or newer than (1) b.
//
// Kubernetes resource versions are opaque strings in the API contract but
// are monotonically increasing integers for a given resource and therefore
// safe to order numerically, mirroring how the Kubernetes watch machinery
// compares them.
func compareResourceVersion(a, b string) (int, error) {
	versionA, err := strconv.ParseUint(a, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid resource version %q: %w", a, err)
	}
	versionB, err := strconv.ParseUint(b, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid resource version %q: %w", b, err)
	}
	switch {
	case versionA < versionB:
		return -1, nil
	case versionA > versionB:
		return 1, nil
	default:
		return 0, nil
	}
}

// Update updates the remote.kubernetes.* component. After the update completes, a
// poll is forced.
func (c *Component) Update(args component.Arguments) (err error) {
	// defer initial poll so the lock is released first
	defer func() {
		if err != nil {
			return
		}
		// Poll after updating and propagate the error if the poll fails. If an error
		// occurred during Update, we don't bother to do anything.
		// It is important to set err and the health so startup works correctly.
		// finishPoll turns observations with an older resource version into a
		// no-op, so a forced poll can never roll the applied contents back.
		err = c.finishPoll(c.pollError())
	}()

	c.mut.Lock()
	defer c.mut.Unlock()

	newArgs := args.(Arguments)

	// Tracking a different resource resets the version high-water mark: the
	// ordering guarantee only applies to observations of the same object.
	if newArgs.Namespace != c.args.Namespace || newArgs.Name != c.args.Name {
		c.synced = false
		c.lastResourceVersion = ""
		c.lastExports = Exports{}
		c.lastPollStatus = ""
	}
	c.args = newArgs

	restConfig, err := c.args.Client.BuildRESTConfig(c.opts.Logger)
	if err != nil {
		return err
	}
	clientset, err := client_go.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}
	c.client = clientset.CoreV1()

	return err
}

// CurrentHealth returns the current health of the component.
func (c *Component) CurrentHealth() component.Health {
	c.healthMut.RLock()
	defer c.healthMut.RUnlock()
	return c.health
}
