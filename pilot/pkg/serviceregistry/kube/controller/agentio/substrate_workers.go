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

package agentio

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"maps"
	"os"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/extensions"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/agentio/substrateapi"
	"istio.io/istio/pkg/env"
)

const substrateRoundRobinServiceConfig = `{"loadBalancingConfig":[{"round_robin":{}}]}`

var (
	substrateListWorkersAddress = env.Register("SUBSTRATE_LIST_WORKERS_ADDRESS", "",
		"Substrate ateapi gRPC target. Empty disables the ListWorkers Actor binding source.")
	substrateListWorkersServerName = env.Register("SUBSTRATE_LIST_WORKERS_SERVER_NAME", "api.ate-system.svc",
		"TLS server name used to verify the Substrate ateapi server certificate.")
	substrateListWorkersCAFile = env.Register("SUBSTRATE_LIST_WORKERS_CA_FILE", "/run/substrate-listworkers/trust-bundle.pem",
		"PEM trust bundle used to verify the Substrate ateapi server certificate.")
	substrateListWorkersClientCredentialBundle = env.Register("SUBSTRATE_LIST_WORKERS_CLIENT_CREDENTIAL_BUNDLE", "/run/substrate-listworkers/credential-bundle.pem",
		"PEM client certificate chain and PKCS8 private key used for mTLS with Substrate ateapi.")
	substrateListWorkersPollInterval = env.Register("SUBSTRATE_LIST_WORKERS_POLL_INTERVAL", 2*time.Second,
		"Interval between successful Substrate ListWorkers snapshots.")
	substrateListWorkersRPCTimeout = env.Register("SUBSTRATE_LIST_WORKERS_RPC_TIMEOUT", 5*time.Second,
		"Timeout for each Substrate ListWorkers page RPC.")
	substrateListWorkersPageSize = env.Register("SUBSTRATE_LIST_WORKERS_PAGE_SIZE", 1000,
		"Requested page size for Substrate ListWorkers, between 1 and 1000.")
)

type substrateWorkerConfig struct {
	Address                string
	ServerName             string
	CAFile                 string
	ClientCredentialBundle string
	PollInterval           time.Duration
	RPCTimeout             time.Duration
	PageSize               int32
}

func substrateWorkerConfigFromEnv() substrateWorkerConfig {
	return substrateWorkerConfig{
		Address:                substrateListWorkersAddress.Get(),
		ServerName:             substrateListWorkersServerName.Get(),
		CAFile:                 substrateListWorkersCAFile.Get(),
		ClientCredentialBundle: substrateListWorkersClientCredentialBundle.Get(),
		PollInterval:           substrateListWorkersPollInterval.Get(),
		RPCTimeout:             substrateListWorkersRPCTimeout.Get(),
		PageSize:               int32(substrateListWorkersPageSize.Get()),
	}
}

func (c substrateWorkerConfig) validate() error {
	if c.Address == "" {
		return fmt.Errorf("Substrate ListWorkers address is required")
	}
	if c.ServerName == "" {
		return fmt.Errorf("Substrate ListWorkers TLS server name is required")
	}
	if c.CAFile == "" {
		return fmt.Errorf("Substrate ListWorkers CA file is required")
	}
	if c.ClientCredentialBundle == "" {
		return fmt.Errorf("Substrate ListWorkers client credential bundle is required")
	}
	if c.PollInterval <= 0 {
		return fmt.Errorf("Substrate ListWorkers poll interval must be positive")
	}
	if c.RPCTimeout <= 0 {
		return fmt.Errorf("Substrate ListWorkers RPC timeout must be positive")
	}
	if c.PageSize <= 0 || c.PageSize > 1000 {
		return fmt.Errorf("Substrate ListWorkers page size must be between 1 and 1000")
	}
	return nil
}

type listWorkersClient interface {
	ListWorkers(context.Context, *substrateapi.ListWorkersRequest, ...grpc.CallOption) (*substrateapi.ListWorkersResponse, error)
}

type workerPodKey struct {
	namespace string
	name      string
	uid       string
}

type substrateWorkerSource struct {
	client   listWorkersClient
	config   substrateWorkerConfig
	onChange func()
	close    func() error

	mu       sync.RWMutex
	bindings map[workerPodKey]*extensions.ActorContext
}

func newSubstrateWorkerSource(config substrateWorkerConfig, onChange func()) (*substrateWorkerSource, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("reading Substrate ateapi CA file: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("Substrate ateapi CA file %q contains no certificates", config.CAFile)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    rootCAs,
		ServerName: config.ServerName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			bundle, err := os.ReadFile(config.ClientCredentialBundle)
			if err != nil {
				return nil, fmt.Errorf("reading Substrate ateapi client credential bundle: %w", err)
			}
			certificate, err := tls.X509KeyPair(bundle, bundle)
			if err != nil {
				return nil, fmt.Errorf("parsing Substrate ateapi client credential bundle: %w", err)
			}
			return &certificate, nil
		},
	}
	conn, err := grpc.NewClient(
		config.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithDefaultServiceConfig(substrateRoundRobinServiceConfig),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Substrate ateapi client: %w", err)
	}
	source := newSubstrateWorkerSourceForClient(substrateapi.NewControlClient(conn), config, onChange)
	source.close = conn.Close
	return source, nil
}

func newSubstrateWorkerSourceForClient(client listWorkersClient, config substrateWorkerConfig, onChange func()) *substrateWorkerSource {
	return &substrateWorkerSource{
		client:   client,
		config:   config,
		onChange: onChange,
		bindings: map[workerPodKey]*extensions.ActorContext{},
	}
}

func (s *substrateWorkerSource) Run(stop <-chan struct{}) {
	if s.close != nil {
		defer func() {
			if err := s.close(); err != nil {
				log.Warnf("Failed to close Substrate ateapi client: %v", err)
			}
		}()
	}
	ticker := time.NewTicker(s.config.PollInterval)
	defer ticker.Stop()
	for {
		if err := s.refresh(context.Background()); err != nil {
			log.Warnf("Failed to refresh Substrate ListWorkers Actor bindings: %v", err)
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func (s *substrateWorkerSource) refresh(ctx context.Context) error {
	nextPageToken := ""
	seenPageTokens := map[string]struct{}{"": {}}
	bindings := map[workerPodKey]*extensions.ActorContext{}
	for {
		rpcCtx, cancel := context.WithTimeout(ctx, s.config.RPCTimeout)
		response, err := s.client.ListWorkers(rpcCtx, &substrateapi.ListWorkersRequest{
			PageSize:  s.config.PageSize,
			PageToken: nextPageToken,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("calling Substrate ListWorkers with page token %q: %w", nextPageToken, err)
		}
		if response == nil {
			return fmt.Errorf("Substrate ListWorkers returned a nil response")
		}
		for _, worker := range response.GetWorkers() {
			key, actor, ok := actorBindingFromSubstrateWorker(worker)
			if !ok {
				continue
			}
			if _, found := bindings[key]; found {
				return fmt.Errorf("Substrate ListWorkers returned duplicate Worker Pod %s/%s uid=%s", key.namespace, key.name, key.uid)
			}
			bindings[key] = actor
		}
		nextPageToken = response.GetNextPageToken()
		if nextPageToken == "" {
			break
		}
		if _, found := seenPageTokens[nextPageToken]; found {
			return fmt.Errorf("Substrate ListWorkers repeated page token %q", nextPageToken)
		}
		seenPageTokens[nextPageToken] = struct{}{}
	}

	s.mu.Lock()
	changed := !maps.EqualFunc(s.bindings, bindings, func(a, b *extensions.ActorContext) bool {
		return proto.Equal(a, b)
	})
	if changed {
		s.bindings = bindings
	}
	s.mu.Unlock()
	if changed && s.onChange != nil {
		s.onChange()
	}
	return nil
}

func actorBindingFromSubstrateWorker(worker *substrateapi.Worker) (workerPodKey, *extensions.ActorContext, bool) {
	if worker == nil || worker.GetMetadata().GetVersion() <= 0 || worker.GetWorkerNamespace() == "" ||
		worker.GetWorkerPod() == "" || worker.GetWorkerPodUid() == "" {
		return workerPodKey{}, nil, false
	}
	assignment := worker.GetStatus().GetAssignment()
	if assignment == nil || assignment.GetActorUid() == "" || assignment.GetActor().GetName() == "" || assignment.GetActor().GetAtespace() == "" {
		return workerPodKey{}, nil, false
	}
	generation := uint64(worker.GetMetadata().GetVersion())
	labels := map[string]string{
		ActorIdentityLabelUID:        assignment.GetActorUid(),
		ActorIdentityLabelName:       assignment.GetActor().GetName(),
		ActorIdentityLabelAtespace:   assignment.GetActor().GetAtespace(),
		ActorIdentityLabelGeneration: strconv.FormatUint(generation, 10),
	}
	if template := assignment.GetActorTemplate(); template != nil {
		if template.GetNamespace() != "" {
			labels[ActorIdentityLabelTemplateNamespace] = template.GetNamespace()
		}
		if template.GetName() != "" {
			labels[ActorIdentityLabelTemplateName] = template.GetName()
		}
	}
	if worker.GetWorkerPool() != "" {
		labels[ActorIdentityLabelWorkerPool] = worker.GetWorkerPool()
	}
	return workerPodKey{
			namespace: worker.GetWorkerNamespace(),
			name:      worker.GetWorkerPod(),
			uid:       worker.GetWorkerPodUid(),
		}, &extensions.ActorContext{
			ActorUid:   assignment.GetActorUid(),
			ActorName:  assignment.GetActor().GetName(),
			Atespace:   assignment.GetActor().GetAtespace(),
			Generation: generation,
			Labels:     labels,
		}, true
}

func (s *substrateWorkerSource) actorContextForWorker(namespace, podName, podUID string) *extensions.ActorContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	actor := s.bindings[workerPodKey{namespace: namespace, name: podName, uid: podUID}]
	if actor == nil {
		return nil
	}
	return proto.Clone(actor).(*extensions.ActorContext)
}
