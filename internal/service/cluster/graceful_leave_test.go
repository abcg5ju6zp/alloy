package cluster

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grafana/ckit/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/alloy/internal/util"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func newGracefulLeaveService(t *testing.T, opts Options) *Service {
	t.Helper()
	opts.Log = util.TestAlloyLogger(t).Slog()
	if opts.NodeName == "" {
		opts.NodeName = "test-node"
	}
	if opts.AdvertiseAddress == "" {
		opts.AdvertiseAddress = freeAddr(t)
	}
	if opts.LeaveConvergeStableFor == 0 {
		opts.LeaveConvergeStableFor = 100 * time.Millisecond
	}
	if opts.LeaveConvergeTimeout == 0 {
		opts.LeaveConvergeTimeout = 5 * time.Second
	}
	if opts.LeaveBroadcastTimeout == 0 {
		opts.LeaveBroadcastTimeout = 2 * time.Second
	}
	if opts.ComponentHandoffTimeout == 0 {
		opts.ComponentHandoffTimeout = time.Second
	}
	if opts.LeaveRecoveryDelay == 0 {
		opts.LeaveRecoveryDelay = time.Second
	}

	s, err := New(opts)
	require.NoError(t, err)
	require.NoError(t, s.node.Start(nil))
	t.Cleanup(s.stop)
	return s
}

func TestLeaveMarkerRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, leaveMarkerDir, leaveMarkerFile)

	// Missing marker is not an error.
	m, err := loadLeaveMarker(path)
	require.NoError(t, err)
	require.Nil(t, m)

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, saveLeaveMarker(path, leaveMarker{Node: "node-1", Time: now, Reason: leaveReasonHandoffTimeout}))

	m, err = loadLeaveMarker(path)
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "node-1", m.Node)
	assert.Equal(t, leaveReasonHandoffTimeout, m.Reason)
	assert.Equal(t, now, m.Time.Truncate(time.Second))

	// Removing and reloading.
	require.NoError(t, removeLeaveMarker(path))
	m, err = loadLeaveMarker(path)
	require.NoError(t, err)
	require.Nil(t, m)

	// Removing a missing marker is not an error.
	require.NoError(t, removeLeaveMarker(path))
}

func TestLeaveMarkerEmptyPath(t *testing.T) {
	t.Parallel()

	require.NoError(t, saveLeaveMarker("", leaveMarker{}))
	m, err := loadLeaveMarker("")
	require.NoError(t, err)
	require.Nil(t, m)
	require.NoError(t, removeLeaveMarker(""))
}

func TestOwnershipFreeze(t *testing.T) {
	t.Parallel()

	s := newTestService(t, Options{EnableClustering: true}, buildPeers(1), func() {})
	defer s.alloyCluster.shutdown()

	assert.False(t, s.alloyCluster.isFrozen())
	s.alloyCluster.freezeOwnershipUpdates()
	assert.True(t, s.alloyCluster.isFrozen())
	s.alloyCluster.resumeOwnershipUpdates()
	assert.False(t, s.alloyCluster.isFrozen())
}

func TestCountRemainingParticipantsAndSignature(t *testing.T) {
	t.Parallel()

	peers := []peer.Peer{
		{Name: "self", State: peer.StateParticipant, Self: true},
		{Name: "a", State: peer.StateParticipant},
		{Name: "b", State: peer.StateParticipant},
		{Name: "c", State: peer.StateTerminating},
		{Name: "d", State: peer.StateViewer},
	}
	assert.Equal(t, 2, countRemainingParticipants(peers, "self"))
	assert.Equal(t, "a:participant,b:participant,c:terminating,d:viewer,self:participant", peersSignature(peers))
}

func TestGracefulLeaveDisabled(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{EnableClustering: false})
	require.NoError(t, s.GracefulLeave(context.Background()))
	assert.Equal(t, peer.StateViewer, s.node.CurrentState())
}

func TestGracefulLeaveNotParticipant(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{EnableClustering: true})
	// Still Viewer: nothing to hand off.
	require.NoError(t, s.GracefulLeave(context.Background()))
	assert.Equal(t, peer.StateViewer, s.node.CurrentState())
}

func TestGracefulLeaveMinimumSizeAbortsAndCanRetry(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering:   true,
		MinimumClusterSize: 3,
	})
	require.NoError(t, s.ChangeState(context.Background(), peer.StateParticipant))

	err := s.GracefulLeave(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrGracefulLeaveAborted), "expected aborted leave, got %v", err)
	require.True(t, errors.Is(err, ErrMinimumClusterSizeNotMet), "expected minimum size cause, got %v", err)

	// The node keeps serving: still Participant and ownership updates resumed.
	assert.Equal(t, peer.StateParticipant, s.node.CurrentState())
	assert.False(t, s.alloyCluster.isFrozen())

	s.leaveMu.Lock()
	assert.False(t, s.leaveRunning)
	assert.False(t, s.leaveFinished)
	s.leaveMu.Unlock()

	// The aborted exit can be retried and aborts again (cluster is still too small).
	err = s.GracefulLeave(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrGracefulLeaveAborted))
	assert.Equal(t, peer.StateParticipant, s.node.CurrentState())
}

func TestGracefulLeaveDiscoveryFailureKeepsService(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering:   true,
		MinimumClusterSize: 0,
		DiscoverPeers: func() ([]string, error) {
			return nil, errors.New("discovery backend unavailable")
		},
	})
	require.NoError(t, s.ChangeState(context.Background(), peer.StateParticipant))

	err := s.GracefulLeave(context.Background())
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrGracefulLeaveAborted), "got %v", err)
	require.True(t, errors.Is(err, ErrPeerDiscoveryFailed), "got %v", err)

	assert.Equal(t, peer.StateParticipant, s.node.CurrentState())
	assert.False(t, s.alloyCluster.isFrozen())
}

func TestGracefulLeaveSingleNodeTransitionsToTerminating(t *testing.T) {
	t.Parallel()

	dataPath := t.TempDir()
	s := newGracefulLeaveService(t, Options{
		EnableClustering:       true,
		MinimumClusterSize:     0,
		DataPath:               dataPath,
		LeaveConvergeStableFor: 100 * time.Millisecond,
	})
	require.NoError(t, s.ChangeState(context.Background(), peer.StateParticipant))

	// A stale marker from an old forced leave is cleared by the clean leave.
	require.NoError(t, saveLeaveMarker(s.leaveMarkerPath, leaveMarker{
		Node:   s.opts.NodeName,
		Time:   time.Now().Add(-time.Hour),
		Reason: leaveReasonHandoffTimeout,
	}))

	require.NoError(t, s.GracefulLeave(context.Background()))
	assert.Equal(t, peer.StateTerminating, s.node.CurrentState())
	assert.True(t, s.alloyCluster.isFrozen())

	s.leaveMu.Lock()
	assert.True(t, s.leaveFinished)
	s.leaveMu.Unlock()

	// Second call is a no-op rather than failing on the invalid transition.
	require.NoError(t, s.GracefulLeave(context.Background()))

	// Marker was removed after the confirmed hand-off.
	marker, err := loadLeaveMarker(s.leaveMarkerPath)
	require.NoError(t, err)
	require.Nil(t, marker)
}

func TestGracefulLeaveConvergenceTimeoutWritesMarker(t *testing.T) {
	t.Parallel()

	dataPath := t.TempDir()
	s := newGracefulLeaveService(t, Options{
		EnableClustering:       true,
		MinimumClusterSize:     0,
		DataPath:               dataPath,
		LeaveConvergeTimeout:   100 * time.Millisecond,
		LeaveConvergeStableFor: time.Minute, // impossible to stabilize within the converge timeout
	})
	require.NoError(t, s.ChangeState(context.Background(), peer.StateParticipant))

	require.NoError(t, s.GracefulLeave(context.Background()))
	assert.Equal(t, peer.StateTerminating, s.node.CurrentState())

	marker, err := loadLeaveMarker(s.leaveMarkerPath)
	require.NoError(t, err)
	require.NotNil(t, marker, "expected a forced-leave recovery marker")
	assert.Equal(t, s.opts.NodeName, marker.Node)
	assert.Equal(t, leaveReasonConvergenceTimeout, marker.Reason)
}

func TestJoinAsParticipantWithoutMarker(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering: true,
		DataPath:         t.TempDir(),
	})
	require.NoError(t, s.JoinAsParticipant(context.Background()))
	assert.Equal(t, peer.StateParticipant, s.node.CurrentState())
}

func TestJoinAsParticipantStaleMarkerPromotesImmediately(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering:   true,
		DataPath:           t.TempDir(),
		LeaveRecoveryDelay: time.Minute,
	})
	require.NoError(t, saveLeaveMarker(s.leaveMarkerPath, leaveMarker{
		Node:   s.opts.NodeName,
		Time:   time.Now().Add(-2 * time.Minute),
		Reason: leaveReasonHandoffTimeout,
	}))

	start := time.Now()
	require.NoError(t, s.JoinAsParticipant(context.Background()))
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Equal(t, peer.StateParticipant, s.node.CurrentState())

	marker, err := loadLeaveMarker(s.leaveMarkerPath)
	require.NoError(t, err)
	require.Nil(t, marker)
}

func TestJoinAsParticipantFreshMarkerDelaysPromotion(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering:   true,
		DataPath:           t.TempDir(),
		LeaveRecoveryDelay: 500 * time.Millisecond,
	})
	require.NoError(t, saveLeaveMarker(s.leaveMarkerPath, leaveMarker{
		Node:   s.opts.NodeName,
		Time:   time.Now(),
		Reason: leaveReasonHandoffTimeout,
	}))

	done := make(chan error, 1)
	go func() {
		done <- s.JoinAsParticipant(context.Background())
	}()

	// While the recovery delay elapses, the node stays a Viewer and takes no
	// write shards.
	select {
	case err := <-done:
		t.Fatalf("JoinAsParticipant returned too early with %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	assert.Equal(t, peer.StateViewer, s.node.CurrentState())

	require.Eventually(t, func() bool {
		select {
		case err := <-done:
			require.NoError(t, err)
			return s.node.CurrentState() == peer.StateParticipant
		default:
			return false
		}
	}, 5*time.Second, 25*time.Millisecond)

	marker, err := loadLeaveMarker(s.leaveMarkerPath)
	require.NoError(t, err)
	require.Nil(t, marker)
}

func TestJoinAsParticipantFreshMarkerContextCancel(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering:   true,
		DataPath:           t.TempDir(),
		LeaveRecoveryDelay: time.Minute,
	})
	require.NoError(t, saveLeaveMarker(s.leaveMarkerPath, leaveMarker{
		Node:   s.opts.NodeName,
		Time:   time.Now(),
		Reason: leaveReasonConvergenceTimeout,
	}))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.JoinAsParticipant(ctx)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, peer.StateViewer, s.node.CurrentState())

	// Marker must survive cancellation so a later restart still honors it.
	marker, err := loadLeaveMarker(s.leaveMarkerPath)
	require.NoError(t, err)
	require.NotNil(t, marker)
}

func TestJoinAsParticipantClusteringDisabled(t *testing.T) {
	t.Parallel()

	s := newGracefulLeaveService(t, Options{
		EnableClustering: false,
		DataPath:         t.TempDir(),
	})
	// Even if a marker somehow exists, it is ignored when clustering is off.
	require.NoError(t, os.WriteFile(filepath.Join(s.opts.DataPath, "ignored"), []byte("x"), 0o644))

	require.NoError(t, s.JoinAsParticipant(context.Background()))
	assert.Equal(t, peer.StateParticipant, s.node.CurrentState())
}
