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

package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type ClusterMode string

const (
	ClusterModeKind     ClusterMode = "kind"
	ClusterModeExisting ClusterMode = "existing"
)

type RetainPolicy string

const (
	RetainNever     RetainPolicy = "never"
	RetainOnFailure RetainPolicy = "on-failure"
	RetainAlways    RetainPolicy = "always"
)

type Config struct {
	Artifacts   ArtifactsConfig   `yaml:"artifacts" json:"artifacts"`
	Cluster     ClusterConfig     `yaml:"cluster" json:"cluster"`
	Lifecycle   LifecycleConfig   `yaml:"lifecycle" json:"lifecycle"`
	Diagnostics DiagnosticsConfig `yaml:"diagnostics" json:"diagnostics"`
}

type ArtifactsConfig struct {
	Dir string `yaml:"dir" json:"dir"`
}

type ClusterConfig struct {
	Mode       ClusterMode `yaml:"mode" json:"mode"`
	Name       string      `yaml:"name" json:"name"`
	Kubeconfig string      `yaml:"kubeconfig" json:"kubeconfig"`
	Context    string      `yaml:"context" json:"context"`
	Reuse      bool        `yaml:"reuse" json:"reuse"`
	Kind       KindConfig  `yaml:"kind" json:"kind"`
}

type KindConfig struct {
	NodeImage string `yaml:"node-image" json:"nodeImage"`
	Config    string `yaml:"config" json:"config"`
}

type LifecycleConfig struct {
	Retain RetainPolicy `yaml:"retain" json:"retain"`
}

type DiagnosticsConfig struct {
	FullOnFailure bool `yaml:"full-on-failure" json:"fullOnFailure"`
	MaxFullDumps  int  `yaml:"max-full-dumps" json:"maxFullDumps"`
}

func DefaultConfig() Config {
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	return Config{
		Artifacts: ArtifactsConfig{Dir: filepath.Join(wd, "artifacts")},
		Cluster:   ClusterConfig{Mode: ClusterModeKind},
		Lifecycle: LifecycleConfig{Retain: RetainNever},
		Diagnostics: DiagnosticsConfig{
			FullOnFailure: true,
			MaxFullDumps:  5,
		},
	}
}

type FlagInputs struct {
	fs *flag.FlagSet

	configFile        *string
	artifactsDir      *string
	clusterMode       *string
	clusterName       *string
	clusterKubeconfig *string
	clusterContext    *string
	clusterReuse      *bool
	kindNodeImage     *string
	kindConfig        *string
	retain            *string
	fullOnFailure     *bool
	maxFullDumps      *int
}

func RegisterFlags(fs *flag.FlagSet) *FlagInputs {
	in := &FlagInputs{fs: fs}
	in.configFile = fs.String("e2e.config", "", "strict framework YAML configuration")
	in.artifactsDir = fs.String("e2e.artifacts.dir", "", "artifact output directory")
	in.clusterMode = fs.String("e2e.cluster.mode", "", "cluster mode: kind or existing")
	in.clusterName = fs.String("e2e.cluster.name", "", "Kind cluster name")
	in.clusterKubeconfig = fs.String("e2e.cluster.kubeconfig", "", "kubeconfig path")
	in.clusterContext = fs.String("e2e.cluster.context", "", "kubeconfig context")
	in.clusterReuse = fs.Bool("e2e.cluster.reuse", false, "reuse a named Kind cluster")
	in.kindNodeImage = fs.String("e2e.cluster.kind.node-image", "", "Kind node image")
	in.kindConfig = fs.String("e2e.cluster.kind.config", "", "Kind configuration file")
	in.retain = fs.String("e2e.lifecycle.retain", "", "retention: never, on-failure, or always")
	in.fullOnFailure = fs.Bool("e2e.diagnostics.full-on-failure", false, "collect full diagnostics on failure")
	in.maxFullDumps = fs.Int("e2e.diagnostics.max-full-dumps", 0, "maximum full diagnostic dumps")
	return in
}

func ResolveConfig(in *FlagInputs, suite Config) (Config, error) {
	if in == nil || in.fs == nil {
		return Config{}, errors.New("e2e flag inputs are required")
	}
	cfg := suite
	if reflect.DeepEqual(cfg, Config{}) {
		cfg = DefaultConfig()
	}

	explicit := in.explicit()
	configPath := os.Getenv("E2E_CONFIG")
	if explicit["e2e.config"] {
		configPath = *in.configFile
	}
	fileFields, err := applyStrictFile(&cfg, configPath)
	if err != nil {
		return Config{}, err
	}
	envFields, err := applyEnvironment(&cfg)
	if err != nil {
		return Config{}, err
	}
	if err := in.applyExplicit(&cfg, explicit); err != nil {
		return Config{}, err
	}

	if cfg.Cluster.Kubeconfig == "" {
		cfg.Cluster.Kubeconfig = os.Getenv("KUBECONFIG")
	}
	reuseSpecified := fileFields["cluster.reuse"] || envFields["cluster.reuse"] || explicit["e2e.cluster.reuse"]
	if cfg.Cluster.Mode == ClusterModeExisting && reuseSpecified {
		return Config{}, errors.New("cluster reuse is valid only with cluster mode kind")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if cfg.Cluster.Mode == ClusterModeKind && cfg.Cluster.Name == "" {
		name, err := uniqueClusterName()
		if err != nil {
			return Config{}, err
		}
		cfg.Cluster.Name = name
	}
	return cfg, nil
}

func (c Config) Validate() error {
	switch c.Cluster.Mode {
	case ClusterModeKind, ClusterModeExisting:
	default:
		return fmt.Errorf("invalid cluster mode %q: expected kind or existing", c.Cluster.Mode)
	}
	switch c.Lifecycle.Retain {
	case RetainNever, RetainOnFailure, RetainAlways:
	default:
		return fmt.Errorf("invalid retain policy %q: expected never, on-failure, or always", c.Lifecycle.Retain)
	}
	if c.Cluster.Mode == ClusterModeKind && c.Cluster.Reuse && strings.TrimSpace(c.Cluster.Name) == "" {
		return errors.New("cluster name is required when reusing a Kind cluster")
	}
	if c.Diagnostics.MaxFullDumps < 0 {
		return errors.New("max full dumps must be non-negative")
	}
	if strings.TrimSpace(c.Artifacts.Dir) == "" {
		return errors.New("artifacts directory is required")
	}
	return nil
}

func (c Config) Redacted() Config {
	if c.Cluster.Kubeconfig != "" {
		c.Cluster.Kubeconfig = "<redacted>"
	}
	return c
}

func (in *FlagInputs) explicit() map[string]bool {
	set := make(map[string]bool)
	in.fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

func (in *FlagInputs) applyExplicit(cfg *Config, set map[string]bool) error {
	if set["e2e.artifacts.dir"] {
		cfg.Artifacts.Dir = *in.artifactsDir
	}
	if set["e2e.cluster.mode"] {
		cfg.Cluster.Mode = ClusterMode(*in.clusterMode)
	}
	if set["e2e.cluster.name"] {
		cfg.Cluster.Name = *in.clusterName
	}
	if set["e2e.cluster.kubeconfig"] {
		cfg.Cluster.Kubeconfig = *in.clusterKubeconfig
	}
	if set["e2e.cluster.context"] {
		cfg.Cluster.Context = *in.clusterContext
	}
	if set["e2e.cluster.reuse"] {
		cfg.Cluster.Reuse = *in.clusterReuse
	}
	if set["e2e.cluster.kind.node-image"] {
		cfg.Cluster.Kind.NodeImage = *in.kindNodeImage
	}
	if set["e2e.cluster.kind.config"] {
		cfg.Cluster.Kind.Config = *in.kindConfig
	}
	if set["e2e.lifecycle.retain"] {
		cfg.Lifecycle.Retain = RetainPolicy(*in.retain)
	}
	if set["e2e.diagnostics.full-on-failure"] {
		cfg.Diagnostics.FullOnFailure = *in.fullOnFailure
	}
	if set["e2e.diagnostics.max-full-dumps"] {
		cfg.Diagnostics.MaxFullDumps = *in.maxFullDumps
	}
	return nil
}

func applyEnvironment(cfg *Config) (map[string]bool, error) {
	set := make(map[string]bool)
	stringValue := func(name, field string, dst *string) {
		if value, ok := os.LookupEnv(name); ok {
			*dst = value
			set[field] = true
		}
	}
	stringValue("E2E_ARTIFACTS_DIR", "artifacts.dir", &cfg.Artifacts.Dir)
	if value, ok := os.LookupEnv("E2E_CLUSTER_MODE"); ok {
		cfg.Cluster.Mode = ClusterMode(value)
		set["cluster.mode"] = true
	}
	stringValue("E2E_CLUSTER_NAME", "cluster.name", &cfg.Cluster.Name)
	stringValue("E2E_CLUSTER_KUBECONFIG", "cluster.kubeconfig", &cfg.Cluster.Kubeconfig)
	stringValue("E2E_CLUSTER_CONTEXT", "cluster.context", &cfg.Cluster.Context)
	stringValue("E2E_CLUSTER_KIND_NODE_IMAGE", "cluster.kind.node-image", &cfg.Cluster.Kind.NodeImage)
	stringValue("E2E_CLUSTER_KIND_CONFIG", "cluster.kind.config", &cfg.Cluster.Kind.Config)
	if value, ok := os.LookupEnv("E2E_LIFECYCLE_RETAIN"); ok {
		cfg.Lifecycle.Retain = RetainPolicy(value)
		set["lifecycle.retain"] = true
	}
	if value, ok := os.LookupEnv("E2E_CLUSTER_REUSE"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("parse E2E_CLUSTER_REUSE: %w", err)
		}
		cfg.Cluster.Reuse = parsed
		set["cluster.reuse"] = true
	}
	if value, ok := os.LookupEnv("E2E_DIAGNOSTICS_FULL_ON_FAILURE"); ok {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return nil, fmt.Errorf("parse E2E_DIAGNOSTICS_FULL_ON_FAILURE: %w", err)
		}
		cfg.Diagnostics.FullOnFailure = parsed
		set["diagnostics.full-on-failure"] = true
	}
	if value, ok := os.LookupEnv("E2E_DIAGNOSTICS_MAX_FULL_DUMPS"); ok {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return nil, fmt.Errorf("parse E2E_DIAGNOSTICS_MAX_FULL_DUMPS: %w", err)
		}
		cfg.Diagnostics.MaxFullDumps = parsed
		set["diagnostics.max-full-dumps"] = true
	}
	return set, nil
}

func uniqueClusterName() (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate cluster name: %w", err)
	}
	return fmt.Sprintf("agentio-e2e-%s-%s", time.Now().UTC().Format("20060102-150405"), hex.EncodeToString(random)), nil
}
