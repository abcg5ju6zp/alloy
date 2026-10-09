package vault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/syntax/alloytypes"
)

func init() {
	component.Register(component.Registration{
		Name:      "remote.vault",
		Stability: featuregate.StabilityGenerallyAvailable,
		Args:      Arguments{},
		Exports:   Exports{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return New(opts, args.(Arguments))
		},
	})
}

// Arguments configures remote.vault.
type Arguments struct {
	Server    string `alloy:"server,attr"`
	Namespace string `alloy:"namespace,attr,optional"`

	Path string `alloy:"path,attr"`
	Key  string `alloy:"key,attr,optional"`

	RereadFrequency time.Duration `alloy:"reread_frequency,attr,optional"`

	ClientOptions ClientOptions `alloy:"client_options,block,optional"`

	// The user *must* provide exactly one Auth blocks. This must be a slice
	// because the enum flag requires a slice and being tagged as optional.
	//
	// TODO(rfratto): allow the enum flag to be used with a non-slice type.

	Auth []AuthArguments `alloy:"auth,enum,optional"`
}

// DefaultArguments holds default settings for Arguments.
var DefaultArguments = Arguments{
	ClientOptions: ClientOptions{
		MinRetryWait: 1000 * time.Millisecond,
		MaxRetryWait: 1500 * time.Millisecond,
		MaxRetries:   2,
		Timeout:      60 * time.Second,
	},
}

// client creates a Vault client from the arguments.
func (a *Arguments) client() (*vault.Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = a.Server
	cfg.MinRetryWait = a.ClientOptions.MinRetryWait
	cfg.MaxRetryWait = a.ClientOptions.MaxRetryWait
	cfg.MaxRetries = a.ClientOptions.MaxRetries
	cfg.Timeout = a.ClientOptions.Timeout

	cli, err := vault.NewClient(cfg)
	if err != nil {
		return cli, err
	}

	if a.Namespace != "" {
		cli.SetNamespace(a.Namespace)
	}
	return cli, nil
}

// SetToDefault implements syntax.Defaulter.
func (a *Arguments) SetToDefault() {
	*a = DefaultArguments
}

// Validate implements syntax.Validator.
func (a *Arguments) Validate() error {
	if len(a.Auth) == 0 {
		return fmt.Errorf("exactly one auth.* block must be specified; found none")
	} else if len(a.Auth) > 1 {
		return fmt.Errorf("exactly one auth.* block must be specified; found %d", len(a.Auth))
	}

	if a.ClientOptions.Timeout == 0 {
		return fmt.Errorf("client_options.timeout must be greater than 0")
	}

	return nil
}

func (a *Arguments) authMethod() authMethod {
	if len(a.Auth) != 1 {
		panic(fmt.Sprintf("remote.vault: found %d auth types, expected 1", len(a.Auth)))
	}
	return a.Auth[0].authMethod()
}

func (a *Arguments) secretStore(cli *vault.Client) secretStore {
	// TODO(rfratto): support different stores (like a logical store).
	return &kvStore{c: cli}
}

// ClientOptions sets extra options on the Client.
type ClientOptions struct {
	MinRetryWait time.Duration `alloy:"min_retry_wait,attr,optional"`
	MaxRetryWait time.Duration `alloy:"max_retry_wait,attr,optional"`
	MaxRetries   int           `alloy:"max_retries,attr,optional"`
	Timeout      time.Duration `alloy:"timeout,attr,optional"`
}

// Exports is the values exported by remote.vault.
type Exports struct {
	// Data holds key-value pairs returned from Vault after retrieving the key.
	// Any keys-value pairs returned from Vault which are not []byte or strings
	// cannot be represented as secrets and are therefore ignored.
	//
	// However, it seems that most secrets engines don't actually return
	// arbitrary data, so this limitation shouldn't cause any issues in practice.
	Data map[string]alloytypes.Secret `alloy:"data,attr"`
}

// errComponentStopped is returned when Update is invoked after Run has exited.
var errComponentStopped = errors.New("component has stopped and no longer accepts updates")

// A session bundles everything tied to one effective configuration: the
// Vault client, the authenticated token, the retrieved secret and the
// managers maintaining their lifetimes.
//
// A session is fully prepared (client created, authentication successful,
// secret read and lifetime watchers prepared) before it replaces the active
// session. If any preparation step fails, the candidate is discarded and the
// previously active session keeps serving with its old token, old secret and
// old lease renewals.
type session struct {
	args Arguments
	cli  *vault.Client

	auth   *tokenManager
	secret *tokenManager

	// cancel stops the session's background processing. It is set by Run when
	// the session becomes supervised; nil for sessions that never reached Run
	// before being superseded.
	cancel context.CancelFunc
	// done is closed once all background loops have exited and the last
	// lifetime watchers are stopped.
	done chan struct{}
}

// requestStop asks the session to stop all background processing. It is safe
// to call on sessions that were never supervised.
func (s *session) requestStop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// dispose releases resources held by a session whose background processing was
// never started.
func (s *session) dispose() {
	s.auth.stopTicker()
	s.secret.stopTicker()
}

// Component implements the remote.vault component.
type Component struct {
	opts    component.Options
	metrics *metrics

	// updateMu serializes configuration updates. Only the fully prepared
	// candidate of the latest Update call can become the active session.
	updateMu sync.Mutex

	// stateMut guards active. Exports are published while holding stateMut so
	// a retiring session can never publish after a newer session took over.
	stateMut sync.RWMutex
	active   *session

	// sessionChanged wakes Run so it supervises the newest active session.
	sessionChanged chan struct{}

	// runLifecycle tracks the lifetime of Run. runCtx is set while Run may
	// supervise sessions; finished is set once Run has exited, after which
	// Updates are rejected.
	runLifecycle sync.Mutex
	runCtx       context.Context
	finished     bool
}

var (
	_ component.Component       = (*Component)(nil)
	_ component.HealthComponent = (*Component)(nil)
	_ component.DebugComponent  = (*Component)(nil)
)

// New creates a new remote.vault component. It will try to immediately read
// the secret from Vault and return an error if the secret can't be read or if
// authentication against the Vault server fails.
func New(opts component.Options, args Arguments) (*Component, error) {
	c := &Component{
		opts:           opts,
		metrics:        newMetrics(opts.Registerer),
		sessionChanged: make(chan struct{}, 1),
	}

	if err := c.Update(args); err != nil {
		return nil, err
	}
	return c, nil
}

// Run runs the remote.vault component, supervising the active session. When a
// newer session is committed, the previous session's background processing is
// canceled and fully stopped before the new one is started.
func (c *Component) Run(ctx context.Context) error {
	c.runLifecycle.Lock()
	c.runCtx = ctx
	c.runLifecycle.Unlock()

	var supervised *session

	defer func() {
		// A session committed while Run was exiting never got supervised;
		// release its idle resources. Updates arriving afterwards are
		// rejected once finished is set.
		c.stateMut.Lock()
		if c.active != nil && c.active != supervised {
			c.active.dispose()
		}
		c.runLifecycle.Lock()
		c.finished = true
		c.runLifecycle.Unlock()
		c.stateMut.Unlock()
	}()

	retire := func(s *session) {
		if s == nil {
			return
		}
		s.requestStop()
		<-s.done
	}

	for {
		c.stateMut.RLock()
		s := c.active
		c.stateMut.RUnlock()

		if s != supervised {
			// Stop the previous session completely (no late status, no
			// lingering renewals) before any processing for the new session
			// starts.
			retire(supervised)

			sessionCtx, cancel := context.WithCancel(ctx)

			c.stateMut.Lock()
			if c.active != s {
				// The candidate was superseded before it was ever supervised;
				// drop it without starting any background processing and
				// re-evaluate the latest session.
				c.stateMut.Unlock()
				cancel()
				continue
			}
			s.cancel = cancel
			c.stateMut.Unlock()

			go c.runSession(sessionCtx, s)
			supervised = s
		}

		select {
		case <-ctx.Done():
			retire(supervised)
			return nil
		case <-c.sessionChanged:
		}
	}
}

// runSession runs all background processing for s until ctx is canceled. It
// closes s.done after every loop has exited and the last lifetime watchers
// have been stopped.
func (c *Component) runSession(ctx context.Context, s *session) {
	defer close(s.done)

	var wg sync.WaitGroup

	// publishSecret is invoked from the secret manager after a successful
	// forced retrieval. It drops the event when the session has already been
	// superseded, so stale sessions can never emit exports. The read lock
	// serializes against the commit swap.
	publishSecret := func(secret *vault.Secret) {
		c.stateMut.RLock()
		defer c.stateMut.RUnlock()

		if c.active != s {
			return
		}
		c.emitExports(secret)
	}

	// Auth token refreshes don't publish exports.
	s.auth.start(ctx, &wg, nil)
	s.secret.start(ctx, &wg, publishSecret)

	wg.Wait()

	// All loops have exited; stop the watchers they were processing so no
	// renewal goroutine outlives the session.
	s.auth.stopWatcher()
	s.secret.stopWatcher()
}

// Update updates the remote.vault component. The new configuration is prepared
// as a candidate session and only takes effect atomically once the client was
// created, authentication succeeded, the secret was read and the lifetime
// watchers are ready. Any failure leaves the active session completely
// unchanged.
func (c *Component) Update(args component.Arguments) error {
	newArgs := args.(Arguments)

	parent := c.updateParentContext()
	if parent == nil {
		return errComponentStopped
	}

	c.updateMu.Lock()
	defer c.updateMu.Unlock()

	candidate, err := c.buildSession(parent, newArgs)
	if err != nil {
		return err
	}
	c.commitSession(candidate)
	return nil
}

// updateParentContext returns the context candidate preparation is bound to.
// It is nil once Run has exited so updates during shutdown are rejected.
func (c *Component) updateParentContext() context.Context {
	c.runLifecycle.Lock()
	defer c.runLifecycle.Unlock()

	if c.finished {
		return nil
	}
	if c.runCtx != nil {
		return c.runCtx
	}
	return context.Background()
}

// buildSession prepares a candidate session without touching the active
// session. The auth manager is prepared first so the client is authenticated
// before reading the secret.
func (c *Component) buildSession(parent context.Context, args Arguments) (*session, error) {
	cli, err := args.client()
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	candidate := &session{
		args: args,
		cli:  cli,
		done: make(chan struct{}),
	}

	authCtx, cancelAuth := context.WithTimeout(parent, tokenManagerInitializeTimeout)
	authManager, err := newTokenManager(authCtx, tokenManagerOptions{
		Log:    c.opts.Logger.With("token_type", "auth"),
		Client: cli,
		Getter: func(ctx context.Context, cli *vault.Client) (*vault.Secret, error) {
			return args.authMethod().vaultAuthenticate(ctx, cli)
		},

		ReadCounter:    c.metrics.authTotal,
		RefreshCounter: c.metrics.authLeaseRenewalTotal,
	})
	cancelAuth()
	if err != nil {
		// Auth failure: discard the candidate entirely. The old client, token
		// and renewal keep running untouched.
		return nil, fmt.Errorf("authenticating to vault: %w", err)
	}
	candidate.auth = authManager

	secretCtx, cancelSecret := context.WithTimeout(parent, tokenManagerInitializeTimeout)
	secretManager, err := newTokenManager(secretCtx, tokenManagerOptions{
		Log:    c.opts.Logger.With("token_type", "secret"),
		Client: cli,
		Getter: func(ctx context.Context, cli *vault.Client) (*vault.Secret, error) {
			return args.secretStore(cli).Read(ctx, &args)
		},
		RefreshInterval: args.RereadFrequency,

		ReadCounter:    c.metrics.secretReadTotal,
		RefreshCounter: c.metrics.secretLeaseRenewalTotal,
	})
	cancelSecret()
	if err != nil {
		// Secret failure: discard the candidate, including the freshly
		// authenticated token (its watcher was never started). The old token,
		// secret and their renewals keep running untouched.
		return nil, fmt.Errorf("reading secret from vault: %w", err)
	}
	candidate.secret = secretManager

	return candidate, nil
}

// commitSession atomically replaces the active session, publishes the new
// exports and retires the previous session. Only Run (supervision, renewal)
// and the newest session may publish component state afterwards.
func (c *Component) commitSession(s *session) {
	c.stateMut.Lock()
	old := c.active
	wasSupervised := old != nil && old.cancel != nil
	c.active = s
	// Publish exports as part of the swap; exports, health and debug info
	// always reference the same configuration.
	c.emitExports(s.secret.currentSecret())
	c.stateMut.Unlock()

	// Wake Run. Coalesced: if updates arrive faster than Run processes them,
	// Run jumps straight to the latest session; intermediate sessions are
	// never supervised.
	select {
	case c.sessionChanged <- struct{}{}:
	default:
	}

	if old == nil {
		return
	}
	if !wasSupervised {
		// Old session was never supervised; release its idle resources.
		old.dispose()
	} else {
		// Stop old renewal loops as promptly as possible; Run joins them
		// before supervising the new session.
		old.requestStop()
	}
}

// emitExports converts the secret into exports and publishes it to the
// controller.
func (c *Component) emitExports(secret *vault.Secret) {
	newExports := Exports{
		Data: make(map[string]alloytypes.Secret),
	}

	for key, value := range secret.Data {
		switch value := value.(type) {
		case string:
			newExports.Data[key] = alloytypes.Secret(value)
		case []byte:
			newExports.Data[key] = alloytypes.Secret(value)

		default:
			// Non-string secrets are ignored.
			c.opts.Logger.Warn(
				"found field in secret which cannot be converted into a string",
				"key", key,
				"type", fmt.Sprintf("%T", value),
			)
		}
	}

	c.opts.OnStateChange(newExports)
}

// activeSupervised reports whether Run has started background processing for
// the currently active session.
func (c *Component) activeSupervised() bool {
	c.stateMut.RLock()
	defer c.stateMut.RUnlock()
	return c.active != nil && c.active.cancel != nil
}

// CurrentHealth returns the current health of the remote.vault component. It
// will be healthy as long as the latest read or renewal of the active session
// was successful.
func (c *Component) CurrentHealth() component.Health {
	c.stateMut.RLock()
	s := c.active
	c.stateMut.RUnlock()

	if s == nil {
		return component.Health{
			Health:     component.HealthTypeUnhealthy,
			Message:    "component has no active session",
			UpdateTime: time.Now(),
		}
	}
	return component.LeastHealthy(
		s.auth.CurrentHealth(),
		s.secret.CurrentHealth(),
	)
}

// DebugInfo returns debug information about the remote.vault component. It
// includes non-sensitive metadata about the current secret.
func (c *Component) DebugInfo() any {
	c.stateMut.RLock()
	s := c.active
	c.stateMut.RUnlock()

	if s == nil {
		return debugInfo{}
	}
	return debugInfo{
		AuthToken: s.auth.DebugInfo(),
		Secret:    s.secret.DebugInfo(),
	}
}

type debugInfo struct {
	AuthToken secretInfo `alloy:"auth_token,block"`
	Secret    secretInfo `alloy:"secret,block"`
}
