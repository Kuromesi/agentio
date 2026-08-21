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
	"os"
	"sort"
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
	onChange func([]workerPodKey)
	close    func() error

	mu       sync.RWMutex
	bindings map[workerPodKey]*extensions.ActorContext
}

func newSubstrateWorkerSource(config substrateWorkerConfig, onChange func([]workerPodKey)) (*substrateWorkerSource, error) {
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

func newSubstrateWorkerSourceForClient(
	client listWorkersClient,
	config substrateWorkerConfig,
	onChange func([]workerPodKey),
) *substrateWorkerSource {
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
		for _, workerWire := range response.GetWorkers() {
			key, actor, ok, err := actorBindingFromWorkerWire(workerWire)
			if err != nil {
				return err
			}
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
	changedSet := make(map[workerPodKey]struct{})
	for key, oldActor := range s.bindings {
		newActor, found := bindings[key]
		if !found || !proto.Equal(oldActor, newActor) {
			changedSet[key] = struct{}{}
		}
	}
	for key, newActor := range bindings {
		oldActor, found := s.bindings[key]
		if !found || !proto.Equal(oldActor, newActor) {
			changedSet[key] = struct{}{}
		}
	}
	changedKeys := make([]workerPodKey, 0, len(changedSet))
	for key := range changedSet {
		changedKeys = append(changedKeys, key)
	}
	sort.Slice(changedKeys, func(i, j int) bool {
		if changedKeys[i].namespace != changedKeys[j].namespace {
			return changedKeys[i].namespace < changedKeys[j].namespace
		}
		if changedKeys[i].name != changedKeys[j].name {
			return changedKeys[i].name < changedKeys[j].name
		}
		return changedKeys[i].uid < changedKeys[j].uid
	})
	if len(changedKeys) > 0 {
		s.bindings = bindings
	}
	s.mu.Unlock()
	if len(changedKeys) > 0 && s.onChange != nil {
		s.onChange(changedKeys)
	}
	return nil
}

func actorBindingFromWorkerWire(workerWire []byte) (workerPodKey, *extensions.ActorContext, bool, error) {
	var current substrateapi.Worker
	currentErr := proto.Unmarshal(workerWire, &current)
	if currentErr == nil && validWorkerPodIdentity(
		current.GetWorkerNamespace(),
		current.GetWorkerPod(),
		current.GetWorkerPodUid(),
		current.GetMetadata().GetVersion(),
	) {
		key, actor, assigned := actorBindingFromSubstrateWorker(&current)
		return key, actor, assigned, nil
	}

	var legacy substrateapi.LegacyWorker
	legacyErr := proto.Unmarshal(workerWire, &legacy)
	if legacyErr == nil && validWorkerPodIdentity(
		legacy.GetWorkerNamespace(),
		legacy.GetWorkerPod(),
		legacy.GetWorkerPodUid(),
		legacy.GetVersion(),
	) {
		key, actor, assigned := actorBindingFromLegacySubstrateWorker(&legacy)
		return key, actor, assigned, nil
	}
	return workerPodKey{}, nil, false, fmt.Errorf(
		"Substrate ListWorkers returned an unsupported Worker wire schema (current decode: %v; legacy decode: %v)",
		currentErr,
		legacyErr,
	)
}

func actorBindingFromSubstrateWorker(worker *substrateapi.Worker) (workerPodKey, *extensions.ActorContext, bool) {
	if worker == nil {
		return workerPodKey{}, nil, false
	}
	assignment := worker.GetStatus().GetAssignment()
	if assignment == nil {
		return workerPodKey{}, nil, false
	}
	templateNamespace, templateName := "", ""
	if template := assignment.GetActorTemplate(); template != nil {
		templateNamespace, templateName = template.GetNamespace(), template.GetName()
	}
	return buildActorBinding(
		worker.GetWorkerNamespace(),
		worker.GetWorkerPod(),
		worker.GetWorkerPodUid(),
		worker.GetWorkerPool(),
		worker.GetMetadata().GetVersion(),
		templateNamespace,
		templateName,
		assignment.GetActor().GetAtespace(),
		assignment.GetActor().GetName(),
		assignment.GetActorUid(),
	)
}

func actorBindingFromLegacySubstrateWorker(worker *substrateapi.LegacyWorker) (workerPodKey, *extensions.ActorContext, bool) {
	if worker == nil || worker.GetAssignment() == nil {
		return workerPodKey{}, nil, false
	}
	assignment := worker.GetAssignment()
	templateNamespace, templateName := "", ""
	if template := assignment.GetActorTemplate(); template != nil {
		templateNamespace, templateName = template.GetNamespace(), template.GetName()
	}
	return buildActorBinding(
		worker.GetWorkerNamespace(),
		worker.GetWorkerPod(),
		worker.GetWorkerPodUid(),
		worker.GetWorkerPool(),
		worker.GetVersion(),
		templateNamespace,
		templateName,
		assignment.GetActor().GetAtespace(),
		assignment.GetActor().GetName(),
		assignment.GetActorUid(),
	)
}

func buildActorBinding(
	namespace, podName, podUID, workerPool string,
	version int64,
	templateNamespace, templateName, actorAtespace, actorName, actorUID string,
) (workerPodKey, *extensions.ActorContext, bool) {
	key := workerPodKey{namespace: namespace, name: podName, uid: podUID}
	if !validWorkerPodIdentity(namespace, podName, podUID, version) ||
		actorUID == "" || actorName == "" || actorAtespace == "" {
		return key, nil, false
	}
	generation := uint64(version)
	labels := map[string]string{
		ActorIdentityLabelUID:        actorUID,
		ActorIdentityLabelName:       actorName,
		LegacyActorIdentityLabelName: actorName,
		ActorIdentityLabelAtespace:   actorAtespace,
		ActorIdentityLabelGeneration: strconv.FormatUint(generation, 10),
	}
	if templateNamespace != "" {
		labels[ActorIdentityLabelTemplateNamespace] = templateNamespace
	}
	if templateName != "" {
		labels[ActorIdentityLabelTemplateName] = templateName
	}
	if workerPool != "" {
		labels[ActorIdentityLabelWorkerPool] = workerPool
	}
	return key, &extensions.ActorContext{
		ActorUid:   actorUID,
		ActorName:  actorName,
		Atespace:   actorAtespace,
		Generation: generation,
		Labels:     labels,
	}, true
}

func validWorkerPodIdentity(namespace, podName, podUID string, version int64) bool {
	return namespace != "" && podName != "" && podUID != "" && version > 0
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
