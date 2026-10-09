// Package cluster implements the cluster service, where multiple instances of
// Alloy connect to each other for work distribution.
package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/grafana/ckit"
	"github.com/grafana/ckit/peer"
	"github.com/grafana/ckit/shard"
	"github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/net/http2"
	"golang.org/x/time/rate"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/service"
	"github.com/grafana/alloy/internal/service/cluster/discovery"
	httpservice "github.com/grafana/alloy/internal/service/http"
	"github.com/grafana/alloy/internal/service/remotecfg"
	"github.com/grafana/alloy/internal/slogadapter"
	"github.com/grafana/alloy/internal/util"
)

const (
	// ServiceName defines the name used for the cluster service.
	ServiceName = "cluster"

	// tokensPerNode is used to decide how many tokens each node should be given in
	// the hash ring. All nodes must use the same value, otherwise they will have
	// different views of the ring and assign work differently.
	//
	// Using 512 tokens strikes a good balance between distribution accuracy and
	// memory consumption. A cluster of 1,000 nodes with 512 tokens per node
	// requires 12MB for the hash ring.
	//
	// Distribution accuracy measures how close a node was to being responsible for
	// exactly 1/N keys during simulation. Simulation tests used a cluster of 10
	// nodes and hashing 100,000 random keys:
	//
	//	512 tokens per node: min 96.1%, median 99.9%, max 103.2% (stddev: 197.9 hashes)
	tokensPerNode = 512

	// maxPeersToLog is the maximum number of peers to log on info level. All peers are logged on debug level.
	maxPeersToLog = 10

	// stateUpdateMinInterval is the minimum time interval between propagating peer changes to Alloy components.
	// This allows to rate limit the number of updates when the cluster is frequently changing (e.g. during rollout).
	stateUpdateMinInterval = time.Second

	// Timing of the graceful leave sequence. The values can be overridden per
	// Service through Options to make the sequence testable.

	// defaultLeaveBroadcastTimeout is how long to wait for the Terminating
	// state to be broadcast to a remote peer.
	defaultLeaveBroadcastTimeout = 10 * time.Second

	// defaultLeaveConvergeTimeout caps how long the node waits for healthy
	// participants to converge on the new hash result before forcing the
	// leave.
	defaultLeaveConvergeTimeout = 20 * time.Second

	// defaultLeaveConvergeStableFor is how long the observed peer set must not
	// change before it is considered converged.
	defaultLeaveConvergeStableFor = 2 * time.Second

	// convergePollInterval is how often the local peer view is polled while
	// waiting for convergence.
	convergePollInterval = 100 * time.Millisecond

	// defaultComponentHandoffTimeout is the per-component deadline for
	// completing a shard hand-off.
	defaultComponentHandoffTimeout = 10 * time.Second

	// defaultLeaveRecoveryDelay is how long a restarted node which finds a
	// forced-leave marker stays in the Viewer state (and therefore takes no
	// write shards) before joining as a Participant again.
	defaultLeaveRecoveryDelay = 30 * time.Second
)

// Options are used to configure the cluster service. Options are constant for
// the lifetime of the cluster service.
type Options struct {
	Log     *slog.Logger          // Where to send logs to.
	Metrics prometheus.Registerer // Where to send metrics to.
	Tracer  trace.TracerProvider  // Where to send traces.

	// EnableClustering toggles clustering as a whole. When EnableClustering is
	// false, the instance of Alloy acts as a single-node cluster, and it is not
	// possible for other nodes to join the cluster.
	EnableClustering bool

	NodeName               string        // Name to use for this node in the cluster.
	AdvertiseAddress       string        // Address to advertise to other nodes in the cluster.
	EnableTLS              bool          // Specifies whether TLS should be used for communication between peers.
	TLSCAPath              string        // Path to the CA file.
	TLSCertPath            string        // Path to the certificate file.
	TLSKeyPath             string        // Path to the key file.
	TLSServerName          string        // Server name to use for TLS communication.
	RejoinInterval         time.Duration // How frequently to rejoin the cluster to address split brain issues.
	ClusterMaxJoinPeers    int           // Number of initial peers to join from the discovered set.
	ClusterName            string        // Name to prevent nodes without this identifier from joining the cluster.
	MinimumClusterSize     int           // Minimum cluster size before admitting traffic to components that use clustering.
	MinimumSizeWaitTimeout time.Duration // Maximum duration to wait for minimum cluster size before proceeding; 0 means no timeout.

	// DataPath is the Alloy data directory. When set, a forced graceful leave
	// (one where the shard hand-off could not be confirmed) persists a
	// recoverable marker under <DataPath>/cluster so that a restarted process
	// does not immediately reclaim write shards it already handed off.
	DataPath string

	// LeaveBroadcastTimeout caps waiting for the Terminating state to be
	// broadcast during a graceful leave. Zero uses defaultLeaveBroadcastTimeout.
	LeaveBroadcastTimeout time.Duration
	// LeaveConvergeTimeout caps how long a graceful leave waits for healthy
	// participants to converge on the new hash result. Zero uses
	// defaultLeaveConvergeTimeout.
	LeaveConvergeTimeout time.Duration
	// LeaveConvergeStableFor is how long the peer view must remain unchanged
	// before it is considered converged. Zero uses
	// defaultLeaveConvergeStableFor.
	LeaveConvergeStableFor time.Duration
	// ComponentHandoffTimeout is the per-component deadline for completing a
	// shard hand-off. Zero uses defaultComponentHandoffTimeout.
	ComponentHandoffTimeout time.Duration
	// LeaveRecoveryDelay is how long a restarted node with a forced-leave
	// marker stays in the Viewer state before participating again. Zero uses
	// defaultLeaveRecoveryDelay.
	LeaveRecoveryDelay time.Duration

	// Function to discover peers to join. If this function is nil or returns an
	// empty slice, no peers will be joined.
	DiscoverPeers discovery.DiscoverFn
}

// Service is the cluster service.
type Service struct {
	log    *slog.Logger
	tracer trace.TracerProvider
	opts   Options

	sharder shard.Sharder
	node    *ckit.Node
	randGen *rand.Rand

	// alloyCluster is given to components via calls to Data() and implements Cluster.
	alloyCluster *alloyCluster
	// notifyClusterChange is used to signal that cluster has changed, and we need to notify all the components
	notifyClusterChange chan struct{}

	// host is the service host captured when Run starts. It is used to
	// enumerate and notify components during a graceful leave.
	hostMu sync.RWMutex
	host   service.Host

	// Marker file written when the node must force a leave without a
	// confirmed hand-off. Empty when no data path is configured.
	leaveMarkerPath string

	leaveMu       sync.Mutex
	leaveRunning  bool
	leaveFinished bool
}

// Component is a component which subscribes to clustering updates.
type Component interface {
	component.Component

	// NotifyClusterChange notifies the component that the state of the cluster
	// has changed.
	//
	// Implementations should ignore calls to this method if they are configured
	// to not utilize clustering.
	NotifyClusterChange()
}

// HandoffComponent is an optional extension of Component implemented by
// components which own cluster-sharded work and can coordinate a graceful
// hand-off when the local node is leaving the cluster.
//
// Components which only implement Component remain compatible: during a
// graceful leave they receive a final NotifyClusterChange call while the
// local node is in the Terminating state, at which point it is excluded from
// write hashing and they drop every locally owned shard. Components that
// need to drain or flush work before dropping a shard (and report when the
// hand-off completed) should implement HandoffComponent instead.
type HandoffComponent interface {
	Component

	// HandoffClusterShards is invoked at most once during a graceful leave,
	// after the node published Terminating and the remaining healthy
	// participants converged on the new shard assignments.
	//
	// Implementations must stop (and, if needed, drain or flush) any work for
	// shards that are no longer owned by this node for writes, and only return
	// once the hand-off is complete. Read-serving work may continue; the node
	// remains an eligible read owner while Terminating.
	//
	// It must be safe to call when the component has clustering disabled (in
	// which case it should be a no-op) and must respect ctx cancellation.
	HandoffClusterShards(ctx context.Context) error
}

// Sentinel errors returned by GracefulLeave.
var (
	// ErrGracefulLeaveAborted wraps the cause of an aborted graceful leave.
	// When returned, the node keeps serving as a Participant and the caller
	// may retry the leave later.
	ErrGracefulLeaveAborted = errors.New("graceful cluster leave aborted")

	// ErrPeerDiscoveryFailed indicates that peers could not be (re)discovered
	// before starting the leave, so the node keeps serving rather than leaving
	// without a confirmed takeover.
	ErrPeerDiscoveryFailed = errors.New("failed to discover peers to hand off to")

	// ErrMinimumClusterSizeNotMet indicates that not enough healthy
	// participants would remain after the leave to satisfy the configured
	// minimum cluster size, so the exit is revoked.
	ErrMinimumClusterSizeNotMet = errors.New("not enough healthy participants remain to satisfy minimum cluster size")
)

// ComponentBlock holds common arguments for clustering settings within a
// component. ComponentBlock is intended to be exposed as a block called
// "clustering".
type ComponentBlock struct {
	Enabled bool `alloy:"enabled,attr"`
}

var (
	_ service.Service            = (*Service)(nil)
	_ httpservice.ServiceHandler = (*Service)(nil)
)

// New returns a new, unstarted instance of the cluster service.
func New(opts Options) (*Service, error) {
	var (
		l = opts.Log
		t = opts.Tracer
	)
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	if t == nil {
		t = noop.NewTracerProvider()
	}

	// Apply graceful leave timing defaults.
	if opts.LeaveBroadcastTimeout == 0 {
		opts.LeaveBroadcastTimeout = defaultLeaveBroadcastTimeout
	}
	if opts.LeaveConvergeTimeout == 0 {
		opts.LeaveConvergeTimeout = defaultLeaveConvergeTimeout
	}
	if opts.LeaveConvergeStableFor == 0 {
		opts.LeaveConvergeStableFor = defaultLeaveConvergeStableFor
	}
	if opts.ComponentHandoffTimeout == 0 {
		opts.ComponentHandoffTimeout = defaultComponentHandoffTimeout
	}
	if opts.LeaveRecoveryDelay == 0 {
		opts.LeaveRecoveryDelay = defaultLeaveRecoveryDelay
	}

	ckitConfig := ckit.Config{
		Name:          opts.NodeName,
		AdvertiseAddr: opts.AdvertiseAddress,
		Log:           slogadapter.GoKit(l.Handler()),
		Sharder:       shard.Ring(tokensPerNode),
		Label:         opts.ClusterName,
		EnableTLS:     opts.EnableTLS,
	}

	httpTransport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return net.DialTimeout(network, addr, calcTimeout(ctx))
		},
	}
	if opts.EnableTLS {
		httpTransport.AllowHTTP = false
		tlsConfig, err := loadTLSConfigFromFile(opts.TLSCAPath, opts.TLSCertPath, opts.TLSKeyPath, opts.TLSServerName)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config from file: %w", err)
		}
		l.Debug(
			"loaded TLS config for cluster http transport",
			"TLSCAPath", opts.TLSCAPath,
			"TLSCertPath", opts.TLSCertPath,
			"TLSKeyPath", opts.TLSKeyPath,
			"TLSServerName", opts.TLSServerName,
		)
		httpTransport.TLSClientConfig = tlsConfig
		httpTransport.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.DialWithDialer(&net.Dialer{Timeout: calcTimeout(ctx)}, network, addr, cfg)
		}
	}
	httpClient := &http.Client{
		Transport: httpTransport,
	}

	node, err := ckit.NewNode(httpClient, ckitConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster node: %w", err)
	}
	if opts.EnableClustering && opts.Metrics != nil {
		if err := opts.Metrics.Register(node.Metrics()); err != nil {
			return nil, fmt.Errorf("failed to register metrics: %w", err)
		}
	}

	s := &Service{
		log:    l,
		tracer: t,
		opts:   opts,

		sharder:             ckitConfig.Sharder,
		node:                node,
		randGen:             rand.New(rand.NewSource(time.Now().UnixNano())),
		notifyClusterChange: make(chan struct{}, 1),
		leaveMarkerPath:     markerPath(opts.DataPath),
	}
	s.alloyCluster = newAlloyCluster(ckitConfig.Sharder, s.triggerClusterChangeNotification, opts, l)

	return s, nil
}

func loadTLSConfigFromFile(TLSCAPath string, TLSCertPath string, TLSKeyPath string, serverName string) (*tls.Config, error) {
	pem, err := os.ReadFile(TLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS CA file: %w", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(pem)
	if !caCertPool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to append CA from PEM with path %s", TLSCAPath)
	}

	cert, err := tls.LoadX509KeyPair(TLSCertPath, TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		ServerName:   serverName,
	}, nil
}

// TODO(rfratto): consider making the max timeout configurable.
// Set a maximum timeout for establishing the connection. If our
// context has a deadline earlier than our timeout, we shrink the
// timeout to it.
func calcTimeout(ctx context.Context) time.Duration {
	timeout := 30 * time.Second
	if dur, ok := deadlineDuration(ctx); ok && dur < timeout {
		timeout = dur
	}
	return timeout
}

func deadlineDuration(ctx context.Context) (d time.Duration, ok bool) {
	if t, ok := ctx.Deadline(); ok {
		return time.Until(t), true
	}
	return 0, false
}

// Definition returns the definition of the cluster service.
func (s *Service) Definition() service.Definition {
	return service.Definition{
		Name:       ServiceName,
		ConfigType: nil, // cluster does not accept configuration.
		DependsOn: []string{
			// Cluster depends on the HTTP service to work properly.
			httpservice.ServiceName,
		},
		Stability: featuregate.StabilityGenerallyAvailable,
	}
}

// ServiceHandler returns the service handler for the clustering service. The
// resulting handler always returns 404 when clustering is disabled.
func (s *Service) ServiceHandler(_ service.Host) (base string, handler http.Handler) {
	base, handler = s.node.Handler()

	if !s.opts.EnableClustering {
		handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "clustering is disabled", http.StatusNotFound)
		})
	}

	return base, handler
}

// ChangeState changes the state of the service. If clustering is enabled,
// ChangeState will block until the state change has been propagated to another
// node; cancel the current context to stop waiting. ChangeState fails if the
// current state cannot move to the provided targetState.
//
// Note that the state must be StateParticipant to receive writes.
func (s *Service) ChangeState(ctx context.Context, targetState peer.State) error {
	return s.node.ChangeState(ctx, targetState)
}

// Run starts the cluster service. It will run until the provided context is
// canceled or there is a fatal error.
func (s *Service) Run(ctx context.Context, host service.Host) error {
	// Stop the node on shutdown.
	defer s.stop()

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Remember the host so GracefulLeave can enumerate running components
	// while they are still alive.
	s.hostMu.Lock()
	s.host = host
	s.hostMu.Unlock()
	defer func() {
		s.hostMu.Lock()
		s.host = nil
		s.hostMu.Unlock()
	}()

	s.node.Observe(ckit.FuncObserver(func(_ []peer.Peer) (reregister bool) {
		if ctx.Err() != nil {
			// Unregister our observer if we exited.
			return false
		}
		s.triggerClusterChangeNotification()
		return true
	}))

	peers, err := s.getRandomPeers()
	if err != nil {
		// Warn when failed to get peers on startup as it can result in a split brain. We do not fail hard here
		// because it would complicate the process of bootstrapping a new cluster.
		s.log.Warn("failed to get peers to join at startup; will create a new cluster", "err", err)
	}

	// We log on info level including all the peers (without any abbreviation), as it's happening only on startup and
	// won't spam too much in most cases. In other cases we should either abbreviate the list or log on debug level.
	s.log.Info(
		"starting cluster node",
		"peers_count", len(peers),
		"peers", strings.Join(peers, ","),
		"advertise_addr", s.opts.AdvertiseAddress,
		"minimum_cluster_size", s.opts.MinimumClusterSize,
		"minimum_size_wait_timeout", s.opts.MinimumSizeWaitTimeout,
	)

	if err := s.node.Start(peers); err != nil {
		s.log.Warn("failed to connect to peers; bootstrapping a new cluster", "err", err)

		err := s.node.Start(nil)
		if err != nil {
			// Fatal failure on startup if we can't start a new cluster.
			// NOTE: currently returning error from `Run` will not be handled correctly: https://github.com/grafana/alloy/issues/843
			s.log.Error("failed to bootstrap a fresh cluster with no peers", "err", err)
			os.Exit(1)
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		limiter := rate.NewLimiter(rate.Every(stateUpdateMinInterval), 1)
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.notifyClusterChange:
				if s.alloyCluster.isFrozen() {
					// A graceful leave is in progress: drop the coalesced
					// notification. Components must keep acting on their
					// frozen ownership view until the explicit hand-off
					// notification is delivered.
					continue
				}
				s.notifyComponentsOfClusterChanges(ctx, limiter, host)
			}
		}
	}()

	if s.opts.EnableClustering && s.opts.RejoinInterval > 0 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			t := time.NewTicker(s.opts.RejoinInterval)
			defer t.Stop()

			for {
				select {
				case <-ctx.Done():
					return

				case <-t.C:
					peers, err := s.getRandomPeers()
					if err != nil {
						s.log.Warn("failed to refresh list of peers", "err", err)
						continue
					}
					s.logPeers("rejoining peers", peers)

					if err := s.node.Start(peers); err != nil {
						s.log.Error("failed to rejoin list of peers", "err", err)
						continue
					}
				}
			}
		}()
	}

	<-ctx.Done()
	return nil
}

func (s *Service) notifyComponentsOfClusterChanges(ctx context.Context, limiter *rate.Limiter, host service.Host) {
	tracer := s.tracer.Tracer("")
	spanCtx, span := tracer.Start(ctx, "NotifyClusterChange", trace.WithSpanKind(trace.SpanKindInternal))

	// Update Ready() state of cluster service that components use. Doing it before the limiter to reduce the time
	// during which the components' view of cluster is not fully consistent (e.g. cluster not Ready() even though
	// the number of peers is sufficient). Calls to `updateReadyState()` will still be effectively rate-limited
	// because only one goroutine performs the notification.
	s.alloyCluster.updateReadyState()

	// Limit how often we notify components about peer changes. At start up we may receive N updates in a period
	// of less than one second. This leads to a lot of unnecessary processing.
	_, spanWait := tracer.Start(spanCtx, "RateLimitWait", trace.WithSpanKind(trace.SpanKindInternal))
	if err := limiter.Wait(ctx); err != nil {
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			// This should never happen, but it should be safe to just ignore it and continue.
			s.log.Warn("failed to wait for rate limiter on peers update", "err", err)
		}
		spanWait.RecordError(err)
	}
	spanWait.End()

	peers := s.node.Peers()
	s.logPeers("peers changed", toStringSlice(peers))
	span.SetAttributes(attribute.Int("peers_count", len(peers)))
	span.SetAttributes(attribute.Int("minimum_cluster_size", s.opts.MinimumClusterSize))

	// Notify all components about the clustering change.
	components := component.GetAllComponents(host, component.InfoOptions{})

	if remoteCfgHost, err := remotecfg.GetHost(host); err == nil {
		components = append(components, component.GetAllComponents(remoteCfgHost, component.InfoOptions{})...)
	}

	for _, comp := range components {
		if ctx.Err() != nil {
			// Stop early if we exited, so we don't do unnecessary work notifying
			// consumers that do not need to be notified.
			break
		}

		clusterComponent, ok := comp.Component.(Component)
		if !ok {
			continue
		}

		_, subSpan := tracer.Start(spanCtx, "NotifyClusterChange", trace.WithSpanKind(trace.SpanKindInternal))
		subSpan.SetAttributes(attribute.String("component_id", comp.ID.String()))

		clusterComponent.NotifyClusterChange()

		subSpan.End()
	}
	span.End()
}

func (s *Service) triggerClusterChangeNotification() {
	select {
	case s.notifyClusterChange <- struct{}{}:
	default:
	}
}

func (s *Service) getRandomPeers() ([]string, error) {
	if !s.opts.EnableClustering || s.opts.DiscoverPeers == nil {
		return nil, nil
	}

	peers, err := s.opts.DiscoverPeers()
	if err != nil {
		return nil, err
	}

	// Debug level log all the peers for troubleshooting.
	s.log.Debug(
		"discovered peers",
		"peers_count", len(peers),
		"peers", strings.Join(peers, ","),
	)

	// Here we return the entire list because we can't take a subset.
	if s.opts.ClusterMaxJoinPeers == 0 || len(peers) < s.opts.ClusterMaxJoinPeers {
		return peers, nil
	}

	// We shuffle the list and return only a subset of the peers.
	s.randGen.Shuffle(len(peers), func(i, j int) {
		peers[i], peers[j] = peers[j], peers[i]
	})
	return peers[:s.opts.ClusterMaxJoinPeers], nil
}

func (s *Service) stop() {
	s.alloyCluster.shutdown()

	// The node is going away. We move to the Terminating state to signal that we
	// should not be owners for write hashing operations anymore. A coordinated
	// GracefulLeave may already have published Terminating (and handed off
	// component shards); nodes which never reached the Participant state
	// (e.g. clustering disabled or an aborted startup) cannot transition to
	// Terminating directly, so there is nothing to announce in that case.
	switch s.node.CurrentState() {
	case peer.StateParticipant:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.node.ChangeState(ctx, peer.StateTerminating); err != nil {
			s.log.Error("failed to change state to Terminating", "err", err)
		}
	case peer.StateTerminating:
		// Already announced by GracefulLeave.
	default:
		s.log.Debug("skipping Terminating state announcement", "state", s.node.CurrentState())
	}

	// The membership protocol is stopped last, after every component above
	// completed its hand-off.
	if err := s.node.Stop(); err != nil {
		s.log.Error("failed to gracefully stop node", "err", err)
	}
}

// GracefulLeave coordinates the local node leaving the cluster while
// components are still running. The sequence is:
//
//  1. Freeze propagation of cluster changes to components so they keep acting
//     on their current ownership view (no new local write ownership).
//  2. (Re)discover peers and verify enough healthy participants would remain
//     to satisfy the minimum cluster size; otherwise the leave is aborted and
//     the node keeps serving.
//  3. Publish the Terminating state, removing the node from write hashing
//     while keeping it eligible for reads, and wait for the remaining healthy
//     participants to converge on the new hash result.
//  4. Notify every sharded component to hand off its shards.
//
// The membership protocol itself is not stopped here; it is stopped by Run's
// shutdown handler after the components have exited.
//
// It returns nil when the leave may proceed, possibly after forcing the leave
// and persisting a recoverable marker. It returns an error wrapping
// ErrGracefulLeaveAborted when the node should keep serving instead.
//
// GracefulLeave is a no-op when clustering is disabled, when the node never
// became a Participant, or after a leave already completed.
func (s *Service) GracefulLeave(ctx context.Context) error {
	if !s.opts.EnableClustering {
		return nil
	}

	// Nodes which never reached the Participant state cannot hand write shards
	// over, and a transition from the Viewer state is invalid. Let the regular
	// shutdown path handle these cases.
	if state := s.node.CurrentState(); state != peer.StateParticipant {
		s.log.Debug("skipping graceful leave: node is not a participant", "state", state)
		return nil
	}

	s.leaveMu.Lock()
	switch {
	case s.leaveFinished:
		s.leaveMu.Unlock()
		return nil
	case s.leaveRunning:
		s.leaveMu.Unlock()
		return fmt.Errorf("graceful cluster leave already in progress")
	default:
		s.leaveRunning = true
	}
	s.leaveMu.Unlock()

	// abort unwinds the freeze and leaves the node serving as a Participant.
	// No Terminating state must have been published yet when abort is called.
	abort := func(cause error) error {
		s.log.Warn("aborting graceful cluster leave; node keeps serving", "err", cause)
		s.alloyCluster.resumeOwnershipUpdates()
		s.leaveMu.Lock()
		s.leaveRunning = false
		s.leaveMu.Unlock()
		// Resync components: the aborted discovery/join attempt may have
		// changed the peer set.
		s.triggerClusterChangeNotification()
		return fmt.Errorf("%w: %w", ErrGracefulLeaveAborted, cause)
	}

	finish := func() error {
		s.leaveMu.Lock()
		s.leaveRunning = false
		s.leaveFinished = true
		s.leaveMu.Unlock()
		return nil
	}

	s.log.Info("starting graceful cluster leave; freezing local shard ownership")
	s.alloyCluster.freezeOwnershipUpdates()

	// Step 1: make sure we can still reach the cluster we intend to hand our
	// shards off to. A discovery failure keeps the node serving instead of
	// leaving into the void.
	if s.opts.DiscoverPeers != nil {
		peers, err := s.getRandomPeers()
		if err != nil {
			return abort(fmt.Errorf("%w: %w", ErrPeerDiscoveryFailed, err))
		}
		if len(peers) > 0 {
			if err := s.node.Start(peers); err != nil {
				return abort(fmt.Errorf("%w: failed to rejoin discovered peers before leaving: %w", ErrPeerDiscoveryFailed, err))
			}
		}
	}

	// Step 2: verify that enough healthy participants remain to take over our
	// write shards and keep the cluster above its minimum size.
	remaining := countRemainingParticipants(s.node.Peers(), s.opts.NodeName)
	if required := s.requiredRemainingParticipants(); required > 0 && remaining < required {
		return abort(fmt.Errorf(
			"%w: %d healthy participant(s) would remain, at least %d are required",
			ErrMinimumClusterSizeNotMet, remaining, required,
		))
	}

	// Step 3: publish Terminating. The local sharder excludes the node from
	// OpReadWrite lookups immediately; OpRead lookups keep considering it.
	s.log.Info("publishing Terminating state for graceful cluster leave")
	broadcastCtx, broadcastCancel := context.WithTimeout(ctx, s.opts.LeaveBroadcastTimeout)
	err := s.node.ChangeState(broadcastCtx, peer.StateTerminating)
	broadcastCancel()
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		// The local state did not change; the leave cannot proceed.
		return abort(fmt.Errorf("failed to publish Terminating state: %w", err))
	}
	if err != nil {
		// The local node is Terminating either way (ckit applies the state
		// before waiting for a broadcast ack), so other nodes may still
		// converge. The convergence wait below decides whether the leave has
		// to be forced.
		s.log.Warn("Terminating state broadcast was not acknowledged in time; waiting for convergence anyway", "err", err)
	}

	// Step 4: wait for the remaining healthy participants to converge on the
	// hash result without us.
	convergeCtx, convergeCancel := context.WithTimeout(ctx, s.opts.LeaveConvergeTimeout)
	defer convergeCancel()
	if err := s.waitForConvergence(convergeCtx, remaining); err != nil {
		s.log.Error("healthy participants did not confirm the new hash result in time; forcing leave and persisting recovery marker", "err", err)
		if markerErr := s.writeLeaveMarker(leaveReasonConvergenceTimeout); markerErr != nil {
			s.log.Error("failed to persist recovery marker", "err", markerErr)
		}
		return finish()
	}
	s.log.Info("remaining participants converged on new hash result", "remaining_participants", remaining)

	// Step 5: notify sharded components to complete their hand-off.
	if hfErr := s.notifyComponentsOfHandoff(ctx); hfErr != nil {
		s.log.Error("one or more components did not complete shard hand-off in time; forcing leave and persisting recovery marker", "err", hfErr)
		if markerErr := s.writeLeaveMarker(leaveReasonHandoffTimeout); markerErr != nil {
			s.log.Error("failed to persist recovery marker", "err", markerErr)
		}
		return finish()
	}

	// Clean hand-off: any stale marker from a previous forced leave no longer
	// applies.
	if err := removeLeaveMarker(s.leaveMarkerPath); err != nil {
		s.log.Warn("failed to remove stale leave recovery marker", "err", err)
	}
	s.log.Info("graceful cluster leave completed")
	return finish()
}

// requiredRemainingParticipants returns the number of healthy participants,
// excluding the leaving node, that must remain for a leave to proceed. A zero
// minimum cluster size disables the check.
func (s *Service) requiredRemainingParticipants() int {
	return s.opts.MinimumClusterSize
}

// waitForConvergence polls the local peer view until it has not changed for
// LeaveConvergeStableFor, the local node is Terminating, and at least
// required participants (other than self) remain. A zero required count only
// enforces stability and the local state.
func (s *Service) waitForConvergence(ctx context.Context, required int) error {
	var (
		lastSignature string
		stableSince   time.Time
		ticker        = time.NewTicker(convergePollInterval)
	)
	defer ticker.Stop()

	check := func() bool {
		peers := s.node.Peers()
		signature := peersSignature(peers)
		if signature != lastSignature {
			lastSignature = signature
			stableSince = time.Now()
			return false
		}
		if time.Since(stableSince) < s.opts.LeaveConvergeStableFor {
			return false
		}

		selfTerminating := false
		for _, p := range peers {
			if p.Self && p.State == peer.StateTerminating {
				selfTerminating = true
				break
			}
		}
		return selfTerminating && countRemainingParticipants(peers, s.opts.NodeName) >= required
	}

	// Evaluate immediately instead of waiting for the first tick.
	if check() {
		return nil
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if check() {
				return nil
			}
		}
	}
}

// notifyComponentsOfHandoff asks every running sharded component to complete
// its hand-off. Components implementing HandoffComponent are awaited with a
// per-component deadline; other cluster components receive a final
// NotifyClusterChange (they drop local shards because the node is no longer a
// write owner); components without clustering support are left untouched.
//
// It returns a non-nil error when at least one component missed its hand-off
// deadline or the context was canceled.
func (s *Service) notifyComponentsOfHandoff(ctx context.Context) error {
	s.hostMu.RLock()
	host := s.host
	s.hostMu.RUnlock()
	if host == nil {
		// Run has not started (or already exited): there are no live
		// components to notify.
		return nil
	}

	components := component.GetAllComponents(host, component.InfoOptions{})
	if remoteCfgHost, err := remotecfg.GetHost(host); err == nil {
		components = append(components, component.GetAllComponents(remoteCfgHost, component.InfoOptions{})...)
	}

	var (
		missed   int
		notified int
	)
	for _, comp := range components {
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted while handing off components: %w", ctx.Err())
		}

		clusterComponent, ok := comp.Component.(Component)
		if !ok {
			// Shardless components keep their regular shutdown behavior.
			continue
		}

		if handoffComponent, ok := comp.Component.(HandoffComponent); ok {
			handoffCtx, cancel := context.WithTimeout(ctx, s.opts.ComponentHandoffTimeout)
			err := handoffComponent.HandoffClusterShards(handoffCtx)
			cancel()
			if err != nil {
				missed++
				s.log.Warn("component did not complete cluster shard hand-off in time", "component_id", comp.ID.String(), "err", err)
				continue
			}
		} else {
			// The node is Terminating: re-evaluating ownership drops every
			// locally owned write shard. Completion is asynchronous for
			// components which do not implement HandoffComponent.
			clusterComponent.NotifyClusterChange()
		}
		notified++
	}

	s.log.Info("notified sharded components of cluster hand-off", "components_notified", notified, "components_missed", missed)
	if missed > 0 {
		return fmt.Errorf("%d component(s) did not complete hand-off within %s", missed, s.opts.ComponentHandoffTimeout)
	}
	return nil
}

// writeLeaveMarker persists the recoverable forced-leave marker.
func (s *Service) writeLeaveMarker(reason string) error {
	if s.leaveMarkerPath == "" {
		s.log.Warn("no data path configured; forced leave will not be persisted and a restart may reclaim handed-off shards")
		return nil
	}
	return saveLeaveMarker(s.leaveMarkerPath, leaveMarker{
		Node:   s.opts.NodeName,
		Time:   time.Now().UTC(),
		Reason: reason,
	})
}

// countRemainingParticipants counts Participant-state peers other than self.
func countRemainingParticipants(peers []peer.Peer, selfName string) int {
	count := 0
	for _, p := range peers {
		if p.Name != selfName && p.State == peer.StateParticipant {
			count++
		}
	}
	return count
}

// peersSignature returns an order-independent signature of the peer set and
// states, used to detect convergence.
func peersSignature(peers []peer.Peer) string {
	names := make([]string, 0, len(peers))
	for _, p := range peers {
		names = append(names, p.Name+":"+p.State.String())
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

// JoinAsParticipant transitions the node to the Participant state after
// honoring a possibly present forced-leave recovery marker.
//
// When a recent marker is found, the node stays in the Viewer state for the
// remainder of the configured recovery delay so that it cannot reclaim write
// shards it already handed off before the restart. The marker is deleted once
// the delay elapsed. Markers older than the recovery delay are treated as
// already recovered. When clustering is disabled this is equivalent to
// ChangeState(StateParticipant).
func (s *Service) JoinAsParticipant(ctx context.Context) error {
	if s.opts.EnableClustering && s.leaveMarkerPath != "" {
		marker, err := loadLeaveMarker(s.leaveMarkerPath)
		if err != nil {
			s.log.Warn("failed to read leave recovery marker; joining cluster normally", "err", err)
		} else if marker != nil {
			wait := s.opts.LeaveRecoveryDelay - time.Since(marker.Time)
			switch {
			case wait <= 0:
				s.log.Info("found expired forced-leave recovery marker; joining cluster as participant", "reason", marker.Reason, "left_at", marker.Time)
			default:
				s.log.Warn(
					"found forced-leave recovery marker; staying in Viewer state before taking write shards",
					"reason", marker.Reason,
					"left_at", marker.Time,
					"recovery_delay", wait,
				)
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
			if err := removeLeaveMarker(s.leaveMarkerPath); err != nil {
				s.log.Warn("failed to remove leave recovery marker", "err", err)
			}
		}
	}
	return s.node.ChangeState(ctx, peer.StateParticipant)
}

// Update implements [service.Service]. It returns an error since the cluster
// service does not support runtime configuration.
func (s *Service) Update(_ any) error {
	return fmt.Errorf("cluster service does not support configuration")
}

// Data returns an instance of [Cluster].
func (s *Service) Data() any {
	return s.alloyCluster
}

func (s *Service) logPeers(msg string, peers []string) {
	// Truncate peers list on info level.
	s.log.Info(
		msg,
		"peers_count", len(peers),
		"min_cluster_size", s.opts.MinimumClusterSize,
		"peers", util.JoinWithTruncation(peers, ",", maxPeersToLog, "..."),
	)
}

func toStringSlice[T any](slice []T) []string {
	s := make([]string, 0, len(slice))
	for _, p := range slice {
		s = append(s, fmt.Sprintf("%v", p))
	}
	return s
}
