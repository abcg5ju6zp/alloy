package vault

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/component"
)

const tokenManagerInitializeTimeout = time.Minute

type getTokenFunc func(ctx context.Context, client *vault.Client) (*vault.Secret, error)

// A tokenManager manages the lifecycle of a single secret within one session:
// either the authentication token or the secret read from Vault.
//
// A tokenManager is constructed only after the initial secret has been
// retrieved successfully and its lifetime watcher (if any) has been prepared.
// Background processing is started afterwards by the owning session. Once the
// owning session is retired, all background processing is stopped and the
// tokenManager must not publish component state anymore.
type tokenManager struct {
	log    *slog.Logger
	cli    *vault.Client
	getter getTokenFunc

	refreshTicker  *ticker
	readCounter    prometheus.Counter
	refreshCounter prometheus.Counter

	// refreshMu serializes forced retrievals so that a ticker-driven re-read
	// and a lifetime-watcher recovery can never run at the same time.
	refreshMu sync.Mutex

	stateMut sync.Mutex
	token    *vault.Secret
	// watcher manages the lifetime of token. It is nil when the token does not
	// need a lifetime watcher (e.g. non-renewable secrets).
	watcher *vault.LifetimeWatcher

	// resetCh is signaled whenever watcher is replaced so the lifecycle loop
	// can pick up the new watcher.
	resetCh chan struct{}

	healthMut sync.RWMutex
	health    component.Health

	debugMut  sync.RWMutex
	debugInfo secretInfo
}

type tokenManagerOptions struct {
	Log    *slog.Logger
	Getter getTokenFunc

	ReadCounter, RefreshCounter prometheus.Counter

	Client          *vault.Client
	RefreshInterval time.Duration
}

// newTokenManager creates a new, unstarted tokenManager. The initial token is
// retrieved from getter synchronously and the lifetime watcher (if needed) is
// prepared before returning, so callers can treat the returned manager as
// ready.
func newTokenManager(ctx context.Context, opts tokenManagerOptions) (*tokenManager, error) {
	tm := &tokenManager{
		log:            opts.Log,
		cli:            opts.Client,
		getter:         opts.Getter,
		refreshTicker:  newTicker(opts.RefreshInterval),
		readCounter:    opts.ReadCounter,
		refreshCounter: opts.RefreshCounter,
		resetCh:        make(chan struct{}, 1),
	}

	token, err := tm.getter(ctx, tm.cli)
	if err != nil {
		return nil, err
	}
	tm.readCounter.Inc()

	watcher, err := newLifetimeWatcher(tm.cli, token)
	if err != nil {
		return nil, err
	}

	tm.token = token
	tm.watcher = watcher

	tm.setHealth(component.Health{
		Health:     component.HealthTypeHealthy,
		Message:    "retrieved token",
		UpdateTime: time.Now(),
	})
	tm.updateDebugInfo(time.Now())

	return tm, nil
}

// start launches the background loops of the tokenManager. The provided
// context must be canceled when the owning session is retired.
//
// onRetrieved, if set, is invoked after every successful forced retrieval
// (ticker tick or lifetime watcher expiry). It is never invoked for the
// initial construction read or after ctx has been canceled.
func (tm *tokenManager) start(ctx context.Context, wg *sync.WaitGroup, onRetrieved func(*vault.Secret)) {
	wg.Add(2)
	go tm.runTicker(ctx, wg, onRetrieved)
	go tm.runLifecycle(ctx, wg, onRetrieved)
}

// runTicker periodically forces a fresh retrieval.
func (tm *tokenManager) runTicker(ctx context.Context, wg *sync.WaitGroup, onRetrieved func(*vault.Secret)) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			tm.refreshTicker.Stop()
			return
		case <-tm.refreshTicker.Chan():
			tm.log.Info("refreshing token")
			if token, ok := tm.refresh(ctx); ok && onRetrieved != nil {
				onRetrieved(token)
			}
		}
	}
}

// runLifecycle processes lifetime watcher events until ctx is canceled or the
// current token does not need a watcher.
func (tm *tokenManager) runLifecycle(ctx context.Context, wg *sync.WaitGroup, onRetrieved func(*vault.Secret)) {
	defer wg.Done()

	// started tracks the watcher whose Start goroutine was launched so a
	// coalesced reset signal never starts the same watcher twice.
	var started *vault.LifetimeWatcher

	for {
		tm.stateMut.Lock()
		w := tm.watcher
		tm.stateMut.Unlock()

		if w == nil {
			// The token does not need a watcher (e.g. a non-renewable
			// secret), but a later forced retrieval may produce one. Wait for
			// that event instead of exiting.
			select {
			case <-ctx.Done():
				return
			case <-tm.resetCh:
				continue
			}
		}
		if w != started {
			go w.Start()
			started = w
		}

		select {
		case <-ctx.Done():
			w.Stop()
			return

		case <-tm.resetCh:
			// watcher was replaced by a forced refresh; loop to pick it up.
			continue

		case <-w.DoneCh():
			// A ctx cancellation also closes the watcher; never recover state
			// for a retiring session.
			if ctx.Err() != nil {
				w.Stop()
				return
			}
			if !tm.isCurrentWatcher(w) {
				// The watcher expired after it had been superseded by a forced
				// refresh; its event must be ignored.
				continue
			}
			tm.handleExpiry(ctx, w, onRetrieved)

		case output := <-w.RenewCh():
			if ctx.Err() != nil || !tm.isCurrentWatcher(w) {
				// Stale renewal from a superseded or retiring watcher; must
				// not publish late state.
				continue
			}
			tm.refreshCounter.Inc()
			tm.log.Debug("token has renewed")
			tm.updateDebugInfo(output.RenewedAt)
		}
	}
}

// handleExpiry is invoked when the lifetime watcher reports that the lease can
// no longer be maintained. It attempts to retrieve a new token; the lifecycle
// loop starts the corresponding new watcher. If retrieval fails, the old
// token is kept and a watcher is re-armed for it so recovery keeps being
// retried.
func (tm *tokenManager) handleExpiry(ctx context.Context, expired *vault.LifetimeWatcher, onRetrieved func(*vault.Secret)) {
	tm.log.Info("token lease ended, retrieving a new token")
	if token, ok := tm.refresh(ctx); ok {
		if onRetrieved != nil {
			onRetrieved(token)
		}
		return
	}

	if ctx.Err() != nil {
		return
	}

	// Recovery failed: keep using the old token, and re-arm a lifetime
	// watcher for it so recovery is retried on the next expiry.
	tm.stateMut.Lock()
	defer tm.stateMut.Unlock()

	if tm.watcher != expired {
		// A concurrent forced refresh already superseded the expired token.
		return
	}

	watcher, err := newLifetimeWatcher(tm.cli, tm.token)
	if err != nil {
		tm.log.Error("failed to create lifetime watcher, lease will not renew automatically", "err", err)
		return
	}
	tm.watcher = watcher
	tm.signalReset()
}

// refresh retrieves a new token from Vault and atomically swaps it in together
// with a new lifetime watcher. On failure the previously retrieved token and
// watcher are kept and health is marked unhealthy.
//
// Once ctx is canceled refresh never mutates or publishes any state.
func (tm *tokenManager) refresh(ctx context.Context) (*vault.Secret, bool) {
	tm.refreshMu.Lock()
	defer tm.refreshMu.Unlock()

	token, err := tm.getter(ctx, tm.cli)

	// The session is shutting down (or the initialization deadline expired);
	// the result, successful or not, must never become visible.
	if ctx.Err() != nil {
		return nil, false
	}
	if err != nil {
		tm.log.Error("failed to retrieve token", "err", err)
		tm.setHealth(component.Health{
			Health:     component.HealthTypeUnhealthy,
			Message:    fmt.Sprintf("failed to retrieve token: %s", err),
			UpdateTime: time.Now(),
		})
		tm.updateDebugInfo(time.Now())
		return nil, false
	}

	tm.readCounter.Inc()

	watcher, err := newLifetimeWatcher(tm.cli, token)
	if err != nil {
		// The token itself is usable; only automatic renewal will be
		// unavailable. Keep the token without a watcher, matching historical
		// behavior.
		tm.log.Error("failed to create lifetime watcher, lease will not renew automatically", "err", err)
	}

	tm.stateMut.Lock()
	oldWatcher := tm.watcher
	tm.token = token
	tm.watcher = watcher
	tm.signalReset()
	tm.stateMut.Unlock()

	// Stop the previous watcher; the lifecycle loop observes the reset signal
	// and starts the prepared replacement.
	if oldWatcher != nil {
		oldWatcher.Stop()
	}

	tm.setHealth(component.Health{
		Health:     component.HealthTypeHealthy,
		Message:    "retrieved token",
		UpdateTime: time.Now(),
	})
	tm.updateDebugInfo(time.Now())

	return token, true
}

// currentSecret returns the most recently retrieved secret.
func (tm *tokenManager) currentSecret() *vault.Secret {
	tm.stateMut.Lock()
	defer tm.stateMut.Unlock()
	return tm.token
}

// currentWatcher returns the lifetime watcher managing the current token, or
// nil when the token does not need one.
func (tm *tokenManager) currentWatcher() *vault.LifetimeWatcher {
	tm.stateMut.Lock()
	defer tm.stateMut.Unlock()
	return tm.watcher
}

// stopWatcher stops the current lifetime watcher. It is called after the
// background loops have exited during session shutdown.
func (tm *tokenManager) stopWatcher() {
	tm.stateMut.Lock()
	w := tm.watcher
	tm.stateMut.Unlock()

	if w != nil {
		w.Stop()
	}
}

// stopTicker releases the forced-refresh ticker without starting the
// background loops, e.g. when a session is discarded before being supervised.
func (tm *tokenManager) stopTicker() {
	tm.refreshTicker.Stop()
}

func (tm *tokenManager) isCurrentWatcher(w *vault.LifetimeWatcher) bool {
	tm.stateMut.Lock()
	defer tm.stateMut.Unlock()
	return tm.watcher == w
}

func (tm *tokenManager) signalReset() {
	select {
	case tm.resetCh <- struct{}{}:
	default:
	}
}

func (tm *tokenManager) setHealth(h component.Health) {
	tm.healthMut.Lock()
	defer tm.healthMut.Unlock()

	tm.health = h
}

func (tm *tokenManager) updateDebugInfo(updateTime time.Time) {
	tm.stateMut.Lock()
	token := tm.token
	tm.stateMut.Unlock()

	tm.debugMut.Lock()
	defer tm.debugMut.Unlock()

	tm.debugInfo = getSecretInfo(token, updateTime)
}

// newLifetimeWatcher prepares a lifetime watcher for secret. It returns nil
// when the secret does not need automatic lifetime management.
func newLifetimeWatcher(cli *vault.Client, secret *vault.Secret) (*vault.LifetimeWatcher, error) {
	if !needsLifecycleWatcher(secret) {
		return nil, nil
	}

	return cli.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret:        secret,
		RenewBehavior: vault.RenewBehaviorIgnoreErrors,
	})
}

// needsLifecycleWatcher determines if a secret needs a lifecycle watcher.
// Secrets only need a lifecycle watcher if they are renewable or have a lease
// duration.
func needsLifecycleWatcher(secret *vault.Secret) bool {
	if secret == nil {
		return false
	}

	if secret.Auth != nil {
		return secret.Auth.Renewable || secret.Auth.LeaseDuration > 0
	}
	return secret.Renewable || secret.LeaseDuration > 0
}

// CurrentHealth returns the health of the tokenManager.
func (tm *tokenManager) CurrentHealth() component.Health {
	tm.healthMut.RLock()
	defer tm.healthMut.RUnlock()

	return tm.health
}

// DebugInfo returns the current DebugInfo for the tokenManager.
func (tm *tokenManager) DebugInfo() secretInfo {
	tm.debugMut.RLock()
	defer tm.debugMut.RUnlock()

	return tm.debugInfo
}

type secretInfo struct {
	LatestRequestID  string    `alloy:"latest_request_id,attr"`
	LastUpdateTime   time.Time `alloy:"last_update_time,attr"`
	SecretExpireTime time.Time `alloy:"secret_expire_time,attr"`
	Renewable        bool      `alloy:"renewable,attr"`
	Warnings         []string  `alloy:"warnings,attr"`
}

func getSecretInfo(secret *vault.Secret, updateTime time.Time) secretInfo {
	if secret == nil {
		return secretInfo{
			LastUpdateTime: updateTime,
			Warnings:       []string{"no secret necessary for configured auth mechanism"},
		}
	}

	return secretInfo{
		LatestRequestID:  secret.RequestID,
		LastUpdateTime:   updateTime,
		SecretExpireTime: secretExpireTime(secret),
		Renewable:        secret.Renewable,
		Warnings:         secret.Warnings,
	}
}

func secretExpireTime(secret *vault.Secret) time.Time {
	ttl, err := secret.TokenTTL()
	if err != nil || ttl == 0 {
		return time.Time{}
	}

	return time.Now().UTC().Add(ttl)
}
