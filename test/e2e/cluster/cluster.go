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
	"fmt"

	"github.com/openkruise/agentio/test/e2e/command"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Mode string

const (
	ModeKind     Mode = "kind"
	ModeExisting Mode = "existing"
)

type Config struct {
	Mode       Mode
	Name       string
	Kubeconfig string
	Context    string
	Reuse      bool
	Kind       KindConfig
}

type KindConfig struct {
	NodeImage string
	Config    string
}

type Cluster struct {
	Name       string
	Kubeconfig string
	Context    string
	Mode       Mode
	Owned      bool

	RESTConfig *rest.Config
	Kube       kubernetes.Interface
	Dynamic    dynamic.Interface
	Discovery  discovery.CachedDiscoveryInterface
	Mapper     meta.RESTMapper

	removeKubeconfig bool
}

type CloseOptions struct {
	Preserve bool
}

type Source interface {
	Open(context.Context, Config) (*Cluster, error)
	Close(context.Context, *Cluster, CloseOptions) error
}

type CommandRunner interface {
	Run(context.Context, command.Request) (command.Result, error)
}

type ClientBuilder func(kubeconfig, contextName string) (*Cluster, error)

type Factory struct {
	Runner       CommandRunner
	BuildClients ClientBuilder
}

func (f Factory) Source(config Config) (Source, error) {
	runner := f.Runner
	if runner == nil {
		runner = command.Runner{}
	}
	builder := f.BuildClients
	if builder == nil {
		builder = BuildClients
	}
	switch config.Mode {
	case ModeKind:
		return KindSource{Runner: runner, BuildClients: builder}, nil
	case ModeExisting:
		return ExistingSource{BuildClients: builder}, nil
	default:
		return nil, fmt.Errorf("unsupported cluster mode %q", config.Mode)
	}
}
