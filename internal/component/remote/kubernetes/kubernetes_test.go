package kubernetes

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/syntax"
	"github.com/grafana/alloy/syntax/alloytypes"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestAlloyUnmarshal(t *testing.T) {
	alloyCfg := `
		name = "foo"
		namespace = "bar"
		poll_frequency = "10m"
		poll_timeout = "1s"`

	var args Arguments
	err := syntax.Unmarshal([]byte(alloyCfg), &args)
	require.NoError(t, err)

	assert.Equal(t, 10*time.Minute, args.PollFrequency)
	assert.Equal(t, time.Second, args.PollTimeout)
	assert.Equal(t, "foo", args.Name)
	assert.Equal(t, "bar", args.Namespace)
}
func TestValidate(t *testing.T) {
	t.Run("0 Poll Freq", func(t *testing.T) {
		args := Arguments{}
		args.SetToDefault()
		args.PollFrequency = 0
		err := args.Validate()
		require.ErrorContains(t, err, "poll_frequency must be greater than 0")
	})
	t.Run("negative Poll timeout", func(t *testing.T) {
		args := Arguments{}
		args.SetToDefault()
		args.PollTimeout = 0
		err := args.Validate()
		require.ErrorContains(t, err, "poll_timeout must not be greater than 0")
	})
}

const (
	testNamespace = "test-ns"
	testName      = "test-resource"
)

// testComponent wraps a Component backed by a fake clientset and records
// every announced state change.
type testComponent struct {
	c         *Component
	clientset *fake.Clientset
	mu        sync.Mutex
	exports   []Exports
}

func newTestComponent(t *testing.T, kind ResourceType, objs ...runtime.Object) *testComponent {
	t.Helper()

	tc := &testComponent{clientset: fake.NewSimpleClientset(objs...)}
	opts := component.Options{
		ID:     "remote.kubernetes." + string(kind) + ".test",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OnStateChange: func(e component.Exports) {
			tc.mu.Lock()
			defer tc.mu.Unlock()
			tc.exports = append(tc.exports, e.(Exports))
		},
	}

	args := Arguments{}
	args.SetToDefault()
	args.Namespace = testNamespace
	args.Name = testName
	args.PollTimeout = 5 * time.Second

	tc.c = &Component{
		opts:   opts,
		kind:   kind,
		args:   args,
		client: tc.clientset.CoreV1(),
		health: component.Health{
			Health:  component.HealthTypeUnknown,
			Message: "component started",
		},
	}
	return tc
}

func (tc *testComponent) appliedVersion() string {
	tc.c.mut.Lock()
	defer tc.c.mut.Unlock()
	return tc.c.lastResourceVersion
}

func (tc *testComponent) currentExports() Exports {
	tc.c.mut.Lock()
	defer tc.c.mut.Unlock()
	return tc.c.lastExports
}

func (tc *testComponent) announced() []Exports {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	out := make([]Exports, len(tc.exports))
	copy(out, tc.exports)
	return out
}

// applyEvent invokes the monotonic event processor under its lock.
func (tc *testComponent) applyEvent(event resourceEvent) error {
	tc.c.mut.Lock()
	defer tc.c.mut.Unlock()
	return tc.c.applyEvent(event)
}

func updateSecretEvent(version string, data map[string][]byte) resourceEvent {
	return resourceEvent{
		eventType:       resourceUpdated,
		resourceVersion: version,
		secret: &corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Namespace:       testNamespace,
				Name:            testName,
				ResourceVersion: version,
			},
			Data: data,
		},
	}
}

func updateConfigMapEvent(version string, data map[string]string) resourceEvent {
	return resourceEvent{
		eventType:       resourceUpdated,
		resourceVersion: version,
		configMap: &corev1.ConfigMap{
			ObjectMeta: v1.ObjectMeta{
				Namespace:       testNamespace,
				Name:            testName,
				ResourceVersion: version,
			},
			Data: data,
		},
	}
}

func deleteEvent(version string) resourceEvent {
	return resourceEvent{eventType: resourceDeleted, resourceVersion: version}
}

func TestCompareResourceVersion(t *testing.T) {
	tests := []struct {
		name        string
		a, b        string
		expect      int
		expectError bool
	}{
		{name: "older", a: "3", b: "10", expect: -1},
		{name: "equal", a: "7", b: "7", expect: 0},
		{name: "newer", a: "42", b: "9", expect: 1},
		{name: "invalid a", a: "old", b: "9", expectError: true},
		{name: "invalid b", a: "9", b: "new", expectError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compareResourceVersion(tc.a, tc.b)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expect, got)
		})
	}
}

// The first synchronization after startup applies whatever the API returns,
// including its exports and health.
func TestPollFirstSyncSecret(t *testing.T) {
	tc := newTestComponent(t, TypeSecret, &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "100"},
		Data:       map[string][]byte{"username": []byte("admin")},
	})

	tc.c.poll()

	announced := tc.announced()
	require.Len(t, announced, 1)
	require.Equal(t, map[string]alloytypes.OptionalSecret{
		"username": {Value: "admin", IsSecret: true},
	}, announced[0].Data)
	require.Equal(t, announced[0].Data, tc.currentExports().Data)
	assert.Equal(t, "100", tc.appliedVersion())

	health := tc.c.CurrentHealth()
	assert.Equal(t, component.HealthTypeHealthy, health.Health)
	assert.Equal(t, "got secret", health.Message)
}

// ConfigMaps keep the existing selection rules: data is exported and not
// treated as secret.
func TestPollFirstSyncConfigMap(t *testing.T) {
	tc := newTestComponent(t, TypeConfigMap, &corev1.ConfigMap{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "100"},
		Data:       map[string]string{"config": "value"},
	})

	tc.c.poll()

	announced := tc.announced()
	require.Len(t, announced, 1)
	require.Equal(t, map[string]alloytypes.OptionalSecret{
		"config": {Value: "value", IsSecret: false},
	}, announced[0].Data)
	assert.Equal(t, component.HealthTypeHealthy, tc.c.CurrentHealth().Health)
}

// A normal single update replaces the exports and advances the applied
// resource version.
func TestPollAppliesNewerVersion(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "5"},
		Data:       map[string][]byte{"k": []byte("v1")},
	}
	tc := newTestComponent(t, TypeSecret, secret)
	tc.c.poll()
	firstVersion := tc.appliedVersion()
	require.NotEmpty(t, firstVersion)

	secret.ResourceVersion = "6"
	secret.Data["k"] = []byte("v2")
	_, err := tc.clientset.CoreV1().Secrets(testNamespace).
		Update(t.Context(), secret, v1.UpdateOptions{})
	require.NoError(t, err)

	tc.c.poll()

	cmp, err := compareResourceVersion(tc.appliedVersion(), firstVersion)
	require.NoError(t, err)
	assert.Equal(t, 1, cmp)
	require.Equal(t, "v2", tc.currentExports().Data["k"].Value)
	require.Len(t, tc.announced(), 2)
	assert.Equal(t, component.HealthTypeHealthy, tc.c.CurrentHealth().Health)
}

// A re-read at a bumped version with identical contents does not announce a
// state change but still advances the version watermark.
func TestPollUnchangedContentsNoStateChange(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "5"},
		Data:       map[string][]byte{"k": []byte("v1")},
	}
	tc := newTestComponent(t, TypeSecret, secret)
	tc.c.poll()
	firstVersion := tc.appliedVersion()

	secret.ResourceVersion = "6"
	_, err := tc.clientset.CoreV1().Secrets(testNamespace).
		Update(t.Context(), secret, v1.UpdateOptions{})
	require.NoError(t, err)

	tc.c.poll()

	require.Len(t, tc.announced(), 1)
	cmp, err := compareResourceVersion(tc.appliedVersion(), firstVersion)
	require.NoError(t, err)
	assert.Equal(t, 1, cmp)
}

// A NotFound read on the first synchronization is reported as a read error
// (preserving the original startup behavior) instead of clearing the
// component. Once the resource appears later, the first successful sync
// applies normally.
func TestPollNotFoundBeforeFirstSyncIsError(t *testing.T) {
	for _, rt := range []ResourceType{TypeSecret, TypeConfigMap} {
		t.Run(string(rt), func(t *testing.T) {
			tc := newTestComponent(t, rt)

			err := tc.c.finishPoll(tc.c.pollError())
			require.Error(t, err)
			require.True(t, apierrors.IsNotFound(err))
			require.False(t, tc.c.synced, "first sync must not be marked complete")
			require.Empty(t, tc.announced())
			assert.Equal(t, component.HealthTypeUnhealthy, tc.c.CurrentHealth().Health)

			if rt == TypeSecret {
				_, err = tc.clientset.CoreV1().Secrets(testNamespace).Create(t.Context(), &corev1.Secret{
					ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "1"},
					Data:       map[string][]byte{"k": []byte("v1")},
				}, v1.CreateOptions{})
			} else {
				_, err = tc.clientset.CoreV1().ConfigMaps(testNamespace).Create(t.Context(), &corev1.ConfigMap{
					ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "1"},
					Data:       map[string]string{"k": "v1"},
				}, v1.CreateOptions{})
			}
			require.NoError(t, err)

			tc.c.poll()
			require.True(t, tc.c.synced)
			require.NotEmpty(t, tc.currentExports().Data)
			assert.Equal(t, component.HealthTypeHealthy, tc.c.CurrentHealth().Health)
		})
	}
}

// A NotFound read is a delete event: exports are cleared and the component
// stays healthy; a re-created resource is picked up afterwards.
func TestPollDeleteAndRecreate(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "5"},
		Data:       map[string][]byte{"k": []byte("v1")},
	}
	tc := newTestComponent(t, TypeSecret, secret)
	tc.c.poll()
	deletedVersion := tc.appliedVersion()

	require.NoError(t, tc.clientset.CoreV1().Secrets(testNamespace).
		Delete(t.Context(), testName, v1.DeleteOptions{}))

	tc.c.poll()

	require.Empty(t, tc.currentExports().Data)
	announced := tc.announced()
	require.Len(t, announced, 2)
	require.Empty(t, announced[1].Data)
	assert.Equal(t, component.HealthTypeHealthy, tc.c.CurrentHealth().Health)
	assert.Equal(t, "secret deleted", tc.c.CurrentHealth().Message)

	recreated := &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName, ResourceVersion: "7"},
		Data:       map[string][]byte{"k": []byte("v2")},
	}
	_, err := tc.clientset.CoreV1().Secrets(testNamespace).
		Create(t.Context(), recreated, v1.CreateOptions{})
	require.NoError(t, err)

	tc.c.poll()

	require.Equal(t, "v2", tc.currentExports().Data["k"].Value)
	cmp, err := compareResourceVersion(tc.appliedVersion(), deletedVersion)
	require.NoError(t, err)
	assert.Equal(t, 1, cmp)
}

// A read failure reports unhealthy and leaves the previous exports in
// effect.
func TestPollReadFailureKeepsPreviousExports(t *testing.T) {
	tc := newTestComponent(t, TypeSecret, &corev1.Secret{
		ObjectMeta: v1.ObjectMeta{Namespace: testNamespace, Name: testName},
		Data:       map[string][]byte{"k": []byte("v1")},
	})
	tc.c.poll()

	tc.clientset.PrependReactor("get", "secrets", func(clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("api server unavailable")
	})

	require.Error(t, tc.c.finishPoll(tc.c.pollError()))

	require.Equal(t, "v1", tc.currentExports().Data["k"].Value)
	assert.Equal(t, component.HealthTypeUnhealthy, tc.c.CurrentHealth().Health)
	require.Contains(t, tc.c.CurrentHealth().Message, "api server unavailable")
}

// An update event older than the applied version is ignored and cannot roll
// exports or the version watermark back.
func TestApplyEventIgnoresOlderUpdate(t *testing.T) {
	tc := newTestComponent(t, TypeSecret)

	require.NoError(t, tc.applyEvent(updateSecretEvent("5", map[string][]byte{"k": []byte("v5")})))

	err := tc.applyEvent(updateSecretEvent("4", map[string][]byte{"k": []byte("v4")}))
	require.ErrorIs(t, err, errStaleResourceVersion)

	require.Equal(t, "v5", tc.currentExports().Data["k"].Value)
	assert.Equal(t, "5", tc.appliedVersion())
	announced := tc.announced()
	require.Len(t, announced, 1)
	require.Equal(t, "v5", announced[0].Data["k"].Value)

	// An equal version is a duplicate and ignored as well.
	err = tc.applyEvent(updateSecretEvent("5", map[string][]byte{"k": []byte("v5-duplicate")}))
	require.ErrorIs(t, err, errStaleResourceVersion)
	require.Equal(t, "v5", tc.currentExports().Data["k"].Value)
}

// A newer update arriving after an older one is applied normally.
func TestApplyEventAppliesOutOfOrderNewerUpdate(t *testing.T) {
	tc := newTestComponent(t, TypeConfigMap)

	require.NoError(t, tc.applyEvent(updateConfigMapEvent("2", map[string]string{"k": "v2"})))
	require.ErrorIs(t, tc.applyEvent(updateConfigMapEvent("1", map[string]string{"k": "v1"})), errStaleResourceVersion)
	require.NoError(t, tc.applyEvent(updateConfigMapEvent("3", map[string]string{"k": "v3"})))

	require.Equal(t, "v3", tc.currentExports().Data["k"].Value)
	assert.Equal(t, "3", tc.appliedVersion())
}

// A delete notification which arrives after a newer version was already read
// is ignored; the component is only cleaned up when no newer version is
// available.
func TestApplyEventIgnoresStaleDelete(t *testing.T) {
	tc := newTestComponent(t, TypeSecret)

	require.NoError(t, tc.applyEvent(updateSecretEvent("5", map[string][]byte{"k": []byte("v5")})))

	// Late delete of the older version 3: a newer version is applied.
	require.ErrorIs(t, tc.applyEvent(deleteEvent("3")), errStaleResourceVersion)
	require.Equal(t, "v5", tc.currentExports().Data["k"].Value)
	assert.Equal(t, "5", tc.appliedVersion())

	// A delete for the current or a newer version clears the component.
	require.NoError(t, tc.applyEvent(deleteEvent("6")))
	require.Empty(t, tc.currentExports().Data)
	assert.Equal(t, "6", tc.appliedVersion())

	// A redelivered update of the deleted version must not resurrect data.
	require.ErrorIs(t, tc.applyEvent(updateSecretEvent("6", map[string][]byte{"k": []byte("v5")})), errStaleResourceVersion)
	require.Empty(t, tc.currentExports().Data)

	// A genuinely newer version after the delete is applied again.
	require.NoError(t, tc.applyEvent(updateSecretEvent("7", map[string][]byte{"k": []byte("v7")})))
	require.Equal(t, "v7", tc.currentExports().Data["k"].Value)
}

// A parse failure of a newer version keeps the previous exports and version
// in place and reports an error; a subsequent well-formed newer version is
// still applied.
func TestApplyEventParseFailureKeepsPreviousVersion(t *testing.T) {
	tc := newTestComponent(t, TypeSecret)

	require.NoError(t, tc.applyEvent(updateSecretEvent("5", map[string][]byte{"k": []byte("v5")})))

	malformed := resourceEvent{eventType: resourceUpdated, resourceVersion: "6"}
	err := tc.applyEvent(malformed)
	require.Error(t, err)
	require.NotErrorIs(t, err, errStaleResourceVersion)

	require.Equal(t, "v5", tc.currentExports().Data["k"].Value)
	assert.Equal(t, "5", tc.appliedVersion())

	require.NoError(t, tc.applyEvent(updateSecretEvent("6", map[string][]byte{"k": []byte("v6")})))
	require.Equal(t, "v6", tc.currentExports().Data["k"].Value)
	assert.Equal(t, "6", tc.appliedVersion())
}

// finishPoll turns stale observations into a no-op: health is not rewritten
// and no error propagates, while real failures are reported unhealthy.
func TestFinishPollStaleEventLeavesHealthUntouched(t *testing.T) {
	tc := newTestComponent(t, TypeSecret)
	require.NoError(t, tc.applyEvent(updateSecretEvent("5", map[string][]byte{"k": []byte("v5")})))

	require.NoError(t, tc.c.finishPoll(errStaleResourceVersion))
	assert.Equal(t, component.HealthTypeUnknown, tc.c.CurrentHealth().Health)

	require.NoError(t, tc.c.finishPoll(nil))
	assert.Equal(t, component.HealthTypeHealthy, tc.c.CurrentHealth().Health)

	require.Error(t, tc.c.finishPoll(errors.New("boom")))
	assert.Equal(t, component.HealthTypeUnhealthy, tc.c.CurrentHealth().Health)
}
