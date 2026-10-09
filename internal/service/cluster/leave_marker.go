package cluster

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// leaveMarkerDir is the directory, relative to the Alloy data path, where
// graceful-leave recovery state is persisted.
const leaveMarkerDir = "cluster"

// leaveMarkerFile is the name of the file which records that the local node
// left the cluster without every component completing a shard hand-off.
//
// The marker is "recoverable": it only delays the node from taking write
// shards again after a restart, it never forbids it permanently. Once the
// recovery delay elapsed the marker is deleted and normal participation
// resumes.
const leaveMarkerFile = "forced-leave.json"

// Leave marker reasons.
const (
	leaveReasonConvergenceTimeout = "convergence_timeout"
	leaveReasonHandoffTimeout     = "component_handoff_timeout"
)

// leaveMarker is the persisted representation of a forced, unconfirmed leave.
type leaveMarker struct {
	// Node is the name of the node which forced the leave.
	Node string `json:"node"`
	// Time is when the marker was written.
	Time time.Time `json:"time"`
	// Reason explains why the hand-off could not be confirmed.
	Reason string `json:"reason"`
}

// markerPath returns the absolute path of the leave marker for the configured
// data path. It returns an empty string when no data path is configured.
func markerPath(dataPath string) string {
	if dataPath == "" {
		return ""
	}
	return filepath.Join(dataPath, leaveMarkerDir, leaveMarkerFile)
}

// saveLeaveMarker atomically writes the marker to path. The parent directory
// is created when necessary.
func saveLeaveMarker(path string, marker leaveMarker) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	bb, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".forced-leave-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if the rename did not happen.
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(bb); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// loadLeaveMarker reads the marker at path. A missing marker returns (nil,
// nil) so callers can treat it like "no forced leave in progress".
func loadLeaveMarker(path string) (*leaveMarker, error) {
	if path == "" {
		return nil, nil
	}

	bb, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	var marker leaveMarker
	if err := json.Unmarshal(bb, &marker); err != nil {
		return nil, err
	}
	return &marker, nil
}

// removeLeaveMarker deletes the marker at path. A missing marker is not an
// error.
func removeLeaveMarker(path string) error {
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
