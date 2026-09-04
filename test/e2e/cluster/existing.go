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

package cluster

import (
	"context"
	"errors"
	"fmt"
)

type ExistingSource struct {
	BuildClients ClientBuilder
}

func (s ExistingSource) Open(_ context.Context, config Config) (*Cluster, error) {
	if s.BuildClients == nil {
		return nil, errors.New("existing cluster client builder is required")
	}
	opened, err := s.BuildClients(config.Kubeconfig, config.Context)
	if err != nil {
		return nil, fmt.Errorf("open existing Kubernetes context %q: %w", config.Context, err)
	}
	opened.Name = config.Name
	opened.Kubeconfig = config.Kubeconfig
	if config.Context != "" {
		opened.Context = config.Context
	}
	opened.Mode = ModeExisting
	opened.Owned = false
	opened.removeKubeconfig = false
	return opened, nil
}

func (ExistingSource) Close(context.Context, *Cluster, CloseOptions) error {
	return nil
}
