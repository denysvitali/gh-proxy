package server

import (
	"context"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
)

// watchPolicy watches the file at path for changes and calls reload whenever
// the content may have changed. It is designed to work correctly with
// Kubernetes ConfigMap volume mounts, which atomically swap a "..data"
// symlink rather than writing the target file in place.
func watchPolicy(ctx context.Context, path string, reload func() error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logrus.WithError(err).Error("policy watcher: failed to create watcher")
		return
	}
	defer func() { _ = watcher.Close() }()

	dir := filepath.Dir(path)
	base := filepath.Base(path)

	if err := watcher.Add(dir); err != nil {
		logrus.WithError(err).WithField("dir", dir).Error("policy watcher: failed to watch directory")
		return
	}
	logrus.WithField("path", path).Info("policy watcher: watching for changes")

	// Coalesce rapid events (e.g. multiple inotify notifications during a
	// single ConfigMap update) before triggering a reload.
	const debounce = 200 * time.Millisecond
	timer := time.NewTimer(debounce)
	timer.Stop()
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			name := filepath.Base(event.Name)
			// Trigger on the policy file itself (plain-file write) or on the
			// "..data" symlink that Kubernetes atomically replaces on every
			// ConfigMap reconciliation.
			if name == base || name == "..data" {
				timer.Reset(debounce)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logrus.WithError(err).Warn("policy watcher: fsnotify error")

		case <-timer.C:
			logrus.WithField("path", path).Info("policy watcher: reloading policy")
			if err := reload(); err != nil {
				logrus.WithError(err).Error("policy watcher: reload failed — keeping current policy")
			}
		}
	}
}
