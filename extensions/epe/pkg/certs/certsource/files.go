// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certsource

import (
	"errors"
	"fmt"
	"os"

	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"istio.io/istio/pkg/filewatcher"
)

// fileSource reads PEM material from three paths. Any path may be empty
// (not configured) or absent on disk (not there yet).
type fileSource struct {
	certPath string
	keyPath  string
	caPath   string
}

func (s fileSource) Name() string { return "files " + s.certPath }

// Load reads the three paths. A missing file is absence, not an error, so an
// unmounted Secret volume leaves the material empty rather than failing; any
// other read error (a permission problem, a directory) is reported so the
// anchors fall back to the system trust store.
func (s fileSource) Load() (certPEM, keyPEM, caPEM []byte, err error) {
	if certPEM, err = readOptionalFile(s.certPath); err != nil {
		return nil, nil, nil, err
	}
	if keyPEM, err = readOptionalFile(s.keyPath); err != nil {
		return nil, nil, nil, err
	}
	if caPEM, err = readOptionalFile(s.caPath); err != nil {
		return nil, nil, nil, err
	}
	return certPEM, keyPEM, caPEM, nil
}

// readOptionalFile returns nil for an unset path or one that does not exist.
func readOptionalFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}

// FromFiles returns a certs.Provider backed by PEM files on disk, requiring a usable
// cert/key pair at construction time. Use it where the material is mandatory,
// such as a server that must present a certificate.
//
// Material is reloaded on filesystem events with a periodic backstop, so
// rotation takes effect without a restart. Everything started here is bounded
// by stop.
func FromFiles(certPath, keyPath, caPath string, stop <-chan struct{}) (certs.Provider, error) {
	// Report the underlying reason rather than just "no identity". The source
	// treats an absent file as a resting state, which is right for the optional
	// case but useless as a startup diagnostic here: the operator needs to know
	// which path is wrong and why.
	for _, path := range []string{certPath, keyPath} {
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("loading the initial certificate: %w", err)
		}
	}
	p := fromFiles(fileSource{certPath: certPath, keyPath: keyPath, caPath: caPath}, stop)
	if !p.hasIdentity() {
		return nil, fmt.Errorf("the certificate at %s and its key at %s are not a usable pair", certPath, keyPath)
	}
	return p, nil
}

// FromFilesOptional is FromFiles without the requirement: absent material is a
// valid resting state that fills in later.
//
// This is the shape a Kubernetes Secret volume mounted with optional: true
// needs. The mount starts empty, kubelet populates it once the Secret exists,
// and the watch picks it up — where reading once at startup would have pinned
// "no client identity" for the life of the process.
func FromFilesOptional(certPath, keyPath, caPath string, stop <-chan struct{}) certs.Provider {
	return fromFiles(fileSource{certPath: certPath, keyPath: keyPath, caPath: caPath}, stop)
}

// fromFiles wires a file source to the shared holder, driving reloads from
// filesystem events.
func fromFiles(src fileSource, stop <-chan struct{}) *dynamicProvider {
	triggers := watchPaths(stop, src.certPath, src.keyPath, src.caPath)
	return newDynamic(src, triggers, stop, reloadPollInterval)
}

// watchPaths returns a channel that fires when any of paths changes.
//
// The watcher keys on the parent directory, so a path that does not exist yet
// still produces events once it appears — which is how a late-populated Secret
// volume is noticed. A path whose watch cannot be registered at all (its
// directory is missing too) is covered by the caller's backstop tick instead;
// that fallback is why this returns no error.
func watchPaths(stop <-chan struct{}, paths ...string) <-chan struct{} {
	logger := ctrllog.Log.WithName("certs")
	watcher := filewatcher.NewWatcher()
	triggers := make(chan struct{}, 1)

	watched := 0
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		// Skip repeats: adding one path twice makes the second registration
		// report an "already being watched" error that means nothing here.
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		if err := watcher.Add(path); err != nil {
			logger.V(1).Info("not watching certificate path; relying on the periodic reload instead",
				"path", path, "error", err)
			continue
		}
		watched++
		go forwardEvents(watcher, path, triggers, stop)
	}

	go func() {
		<-stop
		if err := watcher.Close(); err != nil {
			logger.V(1).Info("closing the certificate watcher failed", "error", err)
		}
	}()
	if watched == 0 {
		logger.V(1).Info("no certificate path could be watched; reloads rely on the periodic backstop")
	}
	return triggers
}

// forwardEvents collapses one path's events onto the shared trigger channel
// until stop closes.
func forwardEvents(watcher filewatcher.FileWatcher, path string, triggers chan<- struct{}, stop <-chan struct{}) {
	logger := ctrllog.Log.WithName("certs")
	// Resolved once: these channels are fixed for the life of the watch, and
	// re-resolving them per iteration takes a lock and cleans the path each
	// time. It also means a Close that shuts them does not spin this loop.
	events := watcher.Events(path)
	errs := watcher.Errors(path)
	for {
		select {
		case <-stop:
			return
		case err, ok := <-errs:
			if !ok {
				return
			}
			logger.Error(err, "certificate watcher error", "path", path)
		case _, ok := <-events:
			if !ok {
				return
			}
			select {
			case triggers <- struct{}{}:
			default: // a reload is already pending and will see this write
			}
		}
	}
}
