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

package kube

import (
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/openkruise/agentio/pkg/features"
)

// LoadConfig builds a REST config from an explicit kubeconfig path, falling
// back to the in-cluster config when the path is empty. Both binaries
// (agentiod and epe) take a -kubeconfig flag with this exact semantics.
func LoadConfig(kubeconfigPath string) (*rest.Config, error) {
	if err := features.ValidateKubernetesAPILimits(); err != nil {
		return nil, err
	}
	var config *rest.Config
	var err error
	if kubeconfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("load in-cluster Kubernetes config: %w", err)
		}
	}
	config.QPS = float32(features.KubernetesAPIQPS)
	config.Burst = features.KubernetesAPIBurst
	return config, nil
}
