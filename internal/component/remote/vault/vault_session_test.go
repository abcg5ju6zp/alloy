package vault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/runtime/componenttest"
	"github.com/grafana/alloy/internal/util"
	"github.com/grafana/alloy/syntax/alloytypes"
)

// fakeVault is a minimal scripted Vault HTTP server used instead of a Docker
// container in the session tests.
type fakeVault struct {
	srv *httptest.Server

	mu    sync.Mutex
	hits  map[string]int
	kv    func(path string) (int, string)
	login func() (int, string)
	renew func() (int, string)
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()

	f := &fakeVault{hits: map[string]int{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		var (
			status int
			body   string
		)
		switch {
		case r.URL.Path == "/v1/auth/custom/login":
			if f.login != nil {
				status, body = f.login()
			}
		case r.URL.Path == "/v1/auth/token/renew-self":
			if f.renew != nil {
				status, body = f.renew()
			}
		case f.kv != nil:
			status, body = f.kv(r.URL.Path)
		}
		f.mu.Unlock()

		if status == 0 {
			status = http.StatusNotFound
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeVault) setKV(fn func(path string) (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kv = fn
}

func (f *fakeVault) setLogin(fn func() (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.login = fn
}

func (f *fakeVault) setRenew(fn func() (int, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.renew = fn
}

func (f *fakeVault) url() string { return f.srv.URL }

func (f *fakeVault) hitsFor(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func kvBody(requestID, value string) string {
	return fmt.Sprintf(`{"request_id":%q,"data":{"data":{"key":%q},"metadata":{"version":1}},"lease_duration":0,"renewable":false}`, requestID, value)
}

func authBody(token string, leaseDuration int, renewable bool) string {
	return fmt.Sprintf(`{"auth":{"client_token":%q,"lease_duration":%d,"renewable":%t}}`, token, leaseDuration, renewable)
}

func tokenArgs(server, key string, reread time.Duration) Arguments {
	return Arguments{
		Server:          server,
		Path:            "secret",
		Key:             key,
		RereadFrequency: reread,
		ClientOptions: ClientOptions{
			MinRetryWait: time.Millisecond,
			MaxRetryWait: 5 * time.Millisecond,
			MaxRetries:   1,
			Timeout:      5 * time.Second,
		},
		Auth: []AuthArguments{{
			AuthToken: &AuthToken{Token: alloytypes.Secret("root")},
		}},
	}
}

func customAuthArgs(server string) Arguments {
	a := tokenArgs(server, "test", 0)
	a.Auth = []AuthArguments{{
		AuthCustom: &AuthCustom{
			Path: "auth/custom/login",
			Data: map[string]alloytypes.Secret{"role": alloytypes.Secret("role1")},
		},
	}}
	return a
}

// runTestComponent builds and runs remote.vault through the test controller,
// returning the concrete component so internals can be inspected.
func runTestComponent(t *testing.T, args Arguments) (context.CancelFunc, *componenttest.Controller, *Component) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ctrl, err := componenttest.NewControllerFromID(util.TestLogger(t), "remote.vault")
	require.NoError(t, err)

	runDone := make(chan struct{})
	go func() {
		_ = ctrl.Run(ctx, args)
		close(runDone)
	}()
	t.Cleanup(func() {
		cancel()
		<-runDone
	})

	require.NoError(t, ctrl.WaitRunning(10*time.Second))

	ic, err := ctrl.GetComponent()
	require.NoError(t, err)

	return cancel, ctrl, ic.(*Component)
}

func activeSession(c *Component) *session {
	c.stateMut.RLock()
	defer c.stateMut.RUnlock()
	return c.active
}

func exportsValue(ctrl *componenttest.Controller) string {
	e := ctrl.Exports()
	if e == nil {
		return ""
	}
	return string(e.(Exports).Data["key"])
}

func requireExports(t *testing.T, ctrl *componenttest.Controller, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return exportsValue(ctrl) == want
	}, 5*time.Second, 10*time.Millisecond, "waiting for exports %q, got %q", want, exportsValue(ctrl))
}

func counterValue(t *testing.T, reg *prometheus.Registry, name string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == name {
			var sum float64
			for _, m := range mf.GetMetric() {
				sum += m.GetCounter().GetValue()
			}
			return sum
		}
	}
	return 0
}

// TestNewFailsWhenSecretMissing ensures a candidate failure during the initial
// build prevents the component from being constructed.
func TestNewFailsWhenSecretMissing(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(_ string) (int, string) {
		return http.StatusNotFound, `{"errors":[]}`
	})

	opts := component.Options{
		ID:            "remote.vault.test",
		Logger:        util.TestLogger(t),
		DataPath:      t.TempDir(),
		Registerer:    prometheus.NewRegistry(),
		OnStateChange: func(component.Exports) {},
	}

	_, err := New(opts, tokenArgs(f.url(), "test", 0))
	require.Error(t, err)
}

// TestFailedSecretUpdateKeepsOldSession: a candidate whose secret read fails
// must not disturb the active session's token, secret, exports, health or
// debug metadata.
func TestFailedSecretUpdateKeepsOldSession(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(path string) (int, string) {
		switch path {
		case "/v1/secret/data/test":
			return http.StatusOK, kvBody("req-v1", "v1")
		default:
			return http.StatusNotFound, `{"errors":[]}`
		}
	})

	_, ctrl, c := runTestComponent(t, tokenArgs(f.url(), "test", 0))
	requireExports(t, ctrl, "v1")

	require.Equal(t, "test", activeSession(c).args.Key)

	before := c.DebugInfo().(debugInfo)

	err := ctrl.Update(tokenArgs(f.url(), "missing", 0))
	require.Error(t, err)
	require.Contains(t, err.Error(), "reading secret from vault")

	// Old session remains the active, healthy configuration.
	require.Equal(t, "test", activeSession(c).args.Key)
	require.Equal(t, "v1", exportsValue(ctrl))
	require.Equal(t, component.HealthTypeHealthy, c.CurrentHealth().Health)
	require.Equal(t, before, c.DebugInfo().(debugInfo))
	require.Equal(t, 1, f.hitsFor("/v1/secret/data/missing"))
}

// TestFailedAuthUpdateKeepsOldSession: a candidate whose authentication fails
// must be discarded before the secret is ever read.
func TestFailedAuthUpdateKeepsOldSession(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(path string) (int, string) {
		if path == "/v1/secret/data/test" {
			return http.StatusOK, kvBody("req-v1", "v1")
		}
		return http.StatusNotFound, `{"errors":[]}`
	})
	f.setLogin(func() (int, string) {
		return http.StatusForbidden, `{"errors":["permission denied"]}`
	})

	_, ctrl, c := runTestComponent(t, tokenArgs(f.url(), "test", 0))
	requireExports(t, ctrl, "v1")

	secretHitsBefore := f.hitsFor("/v1/secret/data/test")

	err := ctrl.Update(customAuthArgs(f.url(), 0))
	require.Error(t, err)
	require.Contains(t, err.Error(), "authenticating to vault")

	// The candidate never reached the secret read and the old token auth
	// session stays active.
	require.Equal(t, secretHitsBefore, f.hitsFor("/v1/secret/data/test"))
	require.Equal(t, "v1", exportsValue(ctrl))
	require.Equal(t, component.HealthTypeHealthy, c.CurrentHealth().Health)
	require.IsType(t, &AuthToken{}, activeSession(c).args.Auth[0].authMethod())
}

// TestSuccessfulSwapStopsOldSession verifies that a successful update starts
// serving the new configuration and fully stops the old session's re-read
// loops and renewals.
func TestSuccessfulSwapStopsOldSession(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(path string) (int, string) {
		switch path {
		case "/v1/secret/data/test":
			return http.StatusOK, kvBody("req-v1", "v1")
		case "/v1/secret/data/other":
			return http.StatusOK, kvBody("req-v2", "v2")
		default:
			return http.StatusNotFound, `{"errors":[]}`
		}
	})

	_, ctrl, c := runTestComponent(t, tokenArgs(f.url(), "test", 25*time.Millisecond))
	requireExports(t, ctrl, "v1")

	// Wait for the old session's ticker to perform periodic re-reads.
	require.Eventually(t, func() bool {
		return f.hitsFor("/v1/secret/data/test") >= 3
	}, 5*time.Second, 5*time.Millisecond)

	require.NoError(t, ctrl.Update(tokenArgs(f.url(), "other", 0)))
	requireExports(t, ctrl, "v2")

	// Health and debug info point at the new configuration.
	require.Equal(t, component.HealthTypeHealthy, c.CurrentHealth().Health)
	require.Equal(t, "req-v2", c.DebugInfo().(debugInfo).Secret.LatestRequestID)

	// Let Run retire the old session, then prove the old secret is no longer
	// being read and the new (reread disabled) secret is read only once.
	require.Eventually(t, func() bool {
		return activeSession(c).args.Key == "other" && c.activeSupervised()
	}, 5*time.Second, time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	oldHits := f.hitsFor("/v1/secret/data/test")
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, oldHits, f.hitsFor("/v1/secret/data/test"), "retired session kept re-reading the old secret")
	require.Equal(t, 1, f.hitsFor("/v1/secret/data/other"), "new session with reread disabled read more than once")
}

// TestPeriodicRereadUpdatesExports covers the scheduled re-read compatibility.
func TestPeriodicRereadUpdatesExports(t *testing.T) {
	f := newFakeVault(t)
	var flipped atomic.Bool
	f.setKV(func(path string) (int, string) {
		if path != "/v1/secret/data/test" {
			return http.StatusNotFound, `{"errors":[]}`
		}
		if flipped.Load() {
			return http.StatusOK, kvBody("req-v2", "v2")
		}
		return http.StatusOK, kvBody("req-v1", "v1")
	})

	_, ctrl, _ := runTestComponent(t, tokenArgs(f.url(), "test", 25*time.Millisecond))
	requireExports(t, ctrl, "v1")

	flipped.Store(true)
	requireExports(t, ctrl, "v2")
}

// TestNonRenewableSecretNeedsNoWatcher covers the non-renewable compatibility.
func TestNonRenewableSecretNeedsNoWatcher(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(path string) (int, string) {
		if path == "/v1/secret/data/test" {
			return http.StatusOK, kvBody("req-v1", "v1")
		}
		return http.StatusNotFound, `{"errors":[]}`
	})

	_, ctrl, c := runTestComponent(t, tokenArgs(f.url(), "test", 0))
	requireExports(t, ctrl, "v1")

	require.Eventually(t, c.activeSupervised, 5*time.Second, time.Millisecond)

	s := activeSession(c)
	require.Nil(t, s.auth.currentSecret())
	require.Nil(t, s.secret.currentWatcher())
	require.Nil(t, s.auth.currentWatcher())
}

// TestAuthLeaseRenewed verifies normal lease renewal drives the renewal metric
// and that updates after shutdown are rejected.
func TestAuthLeaseRenewedAndRejectsUpdatesAfterShutdown(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(path string) (int, string) {
		if path == "/v1/secret/data/test" {
			return http.StatusOK, kvBody("req-v1", "v1")
		}
		return http.StatusNotFound, `{"errors":[]}`
	})
	f.setLogin(func() (int, string) {
		return http.StatusOK, authBody("tok-renewable", 3600, true)
	})
	f.setRenew(func() (int, string) {
		return http.StatusOK, authBody("tok-renewable", 3600, true)
	})

	cancel, ctrl, c := runTestComponent(t, customAuthArgs(f.url(), 0))
	requireExports(t, ctrl, "v1")

	reg := ctrl.PromRegistry
	require.Eventually(t, func() bool {
		return counterValue(t, reg, "remote_vault_auth_lease_renewal_total") > 0
	}, 5*time.Second, 10*time.Millisecond, "auth lease was never renewed")
	require.Equal(t, component.HealthTypeHealthy, c.CurrentHealth().Health)

	// Shut the component down; watchers must stop renewing.
	cancel()
	require.Eventually(t, func() bool {
		c.runLifecycle.Lock()
		defer c.runLifecycle.Unlock()
		return c.finished
	}, 5*time.Second, 10*time.Millisecond)

	renewHits := f.hitsFor("/v1/auth/token/renew-self")
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, renewHits, f.hitsFor("/v1/auth/token/renew-self"), "watcher kept renewing after shutdown")

	// Updates during/after shutdown cannot install a new session.
	err := ctrl.Update(customAuthArgs(f.url(), 0))
	require.ErrorIs(t, err, errComponentStopped)
}

// TestRenewalFailureRecovery verifies the recovery action when the active
// session's lease can no longer be renewed: health goes unhealthy while
// retries keep the old secret serving, then a successful re-authentication
// restores health and stops the retry loop.
func TestRenewalFailureRecovery(t *testing.T) {
	f := newFakeVault(t)
	f.setKV(func(path string) (int, string) {
		if path == "/v1/secret/data/test" {
			return http.StatusOK, kvBody("req-v1", "v1")
		}
		return http.StatusNotFound, `{"errors":[]}`
	})

	var logins atomic.Int32
	f.setLogin(func() (int, string) {
		n := logins.Add(1)
		if n == 1 {
			// Short renewable lease; renewal below always fails.
			return http.StatusOK, authBody("tok-short", 1, true)
		}
		return http.StatusInternalServerError, `{"errors":["login unavailable"]}`
	})
	f.setRenew(func() (int, string) {
		return http.StatusForbidden, `{"errors":["cannot renew"]}`
	})

	_, ctrl, c := runTestComponent(t, customAuthArgs(f.url(), 0))
	requireExports(t, ctrl, "v1")

	// Watcher expiry plus failing re-authentication must surface as unhealthy
	// while exports keep serving the previously read secret.
	require.Eventually(t, func() bool {
		return c.CurrentHealth().Health == component.HealthTypeUnhealthy
	}, 10*time.Second, 10*time.Millisecond)
	require.Equal(t, "v1", exportsValue(ctrl))
	require.Greater(t, logins.Load(), int32(1))

	// Restore authentication with a non-renewable token; health recovers and
	// the retry loop goes idle.
	f.setLogin(func() (int, string) {
		return http.StatusOK, authBody("tok-final", 0, false)
	})

	require.Eventually(t, func() bool {
		return c.CurrentHealth().Health == component.HealthTypeHealthy
	}, 10*time.Second, 10*time.Millisecond)
	require.Equal(t, "v1", exportsValue(ctrl))

	require.Eventually(t, func() bool {
		return c.activeSupervised() && activeSession(c).auth.currentWatcher() == nil
	}, 5*time.Second, 10*time.Millisecond)

	hits := f.hitsFor("/v1/auth/custom/login")
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, hits, f.hitsFor("/v1/auth/custom/login"), "recovery kept re-authenticating after success")
}

// TestConsecutiveUpdatesOnlyLatestWins ensures rapid updates discard older
// candidates: only the newest session is supervised and intermediate sessions
// neither renew nor re-read.
func TestConsecutiveUpdatesOnlyLatestWins(t *testing.T) {
	s1, s2, s3 := newFakeVault(t), newFakeVault(t), newFakeVault(t)
	for i, f := range []*fakeVault{s1, s2, s3} {
		i := i
		f.setKV(func(path string) (int, string) {
			if path == "/v1/secret/data/test" {
				return http.StatusOK, kvBody(fmt.Sprintf("req-%d", i), fmt.Sprintf("v%d", i+1))
			}
			return http.StatusNotFound, `{"errors":[]}`
		})
	}

	_, ctrl, c := runTestComponent(t, tokenArgs(s1.url(), "test", 25*time.Millisecond))
	requireExports(t, ctrl, "v1")
	require.Eventually(t, func() bool {
		return s1.hitsFor("/v1/secret/data/test") >= 3
	}, 5*time.Second, 5*time.Millisecond)

	// Two back-to-back updates; the middle session must never serve. Its
	// ticker interval is deliberately long so a scheduling delay can never
	// make it fire before the session is discarded.
	require.NoError(t, ctrl.Update(tokenArgs(s2.url(), "test", 500*time.Millisecond)))
	require.NoError(t, ctrl.Update(tokenArgs(s3.url(), "test", 500*time.Millisecond)))

	requireExports(t, ctrl, "v3")

	require.Eventually(t, func() bool {
		return activeSession(c).args.Server == s3.url() && c.activeSupervised()
	}, 5*time.Second, 10*time.Millisecond)

	// s2 was read exactly once as a candidate and its ticker never ran.
	require.Equal(t, 1, s2.hitsFor("/v1/secret/data/test"), "intermediate session re-read the secret")

	// s1 is fully retired and stops re-reading; s3 is supervised and tickers.
	s1Hits := s1.hitsFor("/v1/secret/data/test")
	require.Eventually(t, func() bool {
		return s3.hitsFor("/v1/secret/data/test") >= 3
	}, 5*time.Second, 5*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, s1Hits, s1.hitsFor("/v1/secret/data/test"), "retired session kept re-reading")
}
