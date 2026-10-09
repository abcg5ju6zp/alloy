package testcomponent

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/alloy/internal/component"
	"github.com/grafana/alloy/internal/featuregate"
	"github.com/grafana/alloy/internal/service/cluster"
)

func init() {
	component.Register(component.Registration{
		Name:      "testcomponents.cluster_handoff_tracker",
		Stability: featuregate.StabilityGenerallyAvailable,
		Args:      ClusterHandoffTrackerConfig{},

		Build: func(opts component.Options, args component.Arguments) (component.Component, error) {
			return NewClusterHandoffTracker(opts, args.(ClusterHandoffTrackerConfig))
		},
	})
}

// ClusterHandoffTrackerConfig configures the handoff tracker test component.
type ClusterHandoffTrackerConfig struct {
	// HandoffLag is how long HandoffClusterShards blocks before reporting
	// completion. It is used to simulate components which are slow to hand
	// their shards off.
	HandoffLag time.Duration `alloy:"handoff_lag,attr,optional"`
}

// ClusterHandoffTracker is a sharded component used by cluster e2e tests to
// observe the graceful leave sequence. It records how often it was asked to
// hand its shards off.
type ClusterHandoffTracker struct {
	opts component.Options

	mut        sync.Mutex
	handoffLag time.Duration

	handoffTotal prometheus.Counter
}

var _ cluster.HandoffComponent = (*ClusterHandoffTracker)(nil)

// NewClusterHandoffTracker creates a new ClusterHandoffTracker.
func NewClusterHandoffTracker(o component.Options, c ClusterHandoffTrackerConfig) (*ClusterHandoffTracker, error) {
	handoffTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cluster_handoffs_total",
		Help: "Number of times the component was asked to hand cluster shards off.",
	})
	if err := o.Registerer.Register(handoffTotal); err != nil {
		return nil, err
	}
	return &ClusterHandoffTracker{
		opts:         o,
		handoffLag:   c.HandoffLag,
		handoffTotal: handoffTotal,
	}, nil
}

// Run implements component.Component.
func (c *ClusterHandoffTracker) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Update implements component.Component.
func (c *ClusterHandoffTracker) Update(args component.Arguments) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	c.handoffLag = args.(ClusterHandoffTrackerConfig).HandoffLag
	return nil
}

// NotifyClusterChange implements cluster.Component.
func (c *ClusterHandoffTracker) NotifyClusterChange() {
	// No-op: ownership is only relevant during HandoffClusterShards.
}

// HandoffClusterShards implements cluster.HandoffComponent. It waits for the
// configured lag (respecting ctx) before reporting the hand-off as completed.
func (c *ClusterHandoffTracker) HandoffClusterShards(ctx context.Context) error {
	c.mut.Lock()
	lag := c.handoffLag
	c.mut.Unlock()

	c.opts.Logger.Info("HandoffClusterShards invoked", "lag", lag)
	if lag > 0 {
		timer := time.NewTimer(lag)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	c.handoffTotal.Inc()
	c.opts.Logger.Info("HandoffClusterShards completed")
	return nil
}
