package sandbox

import (
	"reflect"
	"testing"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube/controller/sandbox/extensions"
)

func TestApplySandboxConfig_BasicOverride(t *testing.T) {
	t.Run("ext_proc set and default ignored labels preserved", func(t *testing.T) {
		defaults := model.DefaultSandboxControllerConfig()
		yml := `
sandboxExtProc:
  service: "ext-proc.example.com"
  port: 9090
`
		got, err := applySandboxConfig(yml, defaults)
		if err != nil {
			t.Fatalf("applySandboxConfig failed: %v", err)
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "ext-proc.example.com" {
			t.Errorf("service: expected ext-proc.example.com, got %s", extProc.GetService())
		}
		if extProc.GetPort() != 9090 {
			t.Errorf("port: expected 9090, got %d", extProc.GetPort())
		}

		// Default ignored labels should be preserved since override YAML does not include them.
		wantLabels := defaults.GetSandboxIgnoredLabels()
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("sandboxIgnoredLabels: expected %v, got %v", wantLabels, gotLabels)
		}
	})
}

func TestApplySandboxConfig_FullSubMessageReplacement(t *testing.T) {
	t.Run("override replaces entire sub-message, unset fields reset to zero", func(t *testing.T) {
		base := &model.SandboxConfig{
			SandboxConfig: &extensions.SandboxConfig{
				SandboxExtProc: &extensions.ExtProcProvider{
					Service: "old.example.com",
					Port:    8080,
				},
			},
		}
		// Override only sets service; port is absent so it should become 0.
		yml := `
sandboxExtProc:
  service: "new.example.com"
`
		got, err := applySandboxConfig(yml, base)
		if err != nil {
			t.Fatalf("applySandboxConfig failed: %v", err)
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "new.example.com" {
			t.Errorf("service: expected new.example.com, got %s", extProc.GetService())
		}
		// Key semantic difference from old deep-merge: port is NOT preserved from base.
		if extProc.GetPort() != 0 {
			t.Errorf("port: expected 0 (reset), got %d", extProc.GetPort())
		}
	})
}

func TestApplySandboxConfig_RepeatedFieldReplacement(t *testing.T) {
	t.Run("override fully replaces repeated field", func(t *testing.T) {
		base := &model.SandboxConfig{
			SandboxConfig: &extensions.SandboxConfig{
				SandboxIgnoredLabels: []string{"a", "b"},
			},
		}
		yml := `
sandboxIgnoredLabels:
  - "c"
`
		got, err := applySandboxConfig(yml, base)
		if err != nil {
			t.Fatalf("applySandboxConfig failed: %v", err)
		}

		want := []string{"c"}
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, want) {
			t.Errorf("sandboxIgnoredLabels: expected %v, got %v", want, gotLabels)
		}
	})
}

func TestApplySandboxConfig_MultiLayerMerge(t *testing.T) {
	t.Run("default -> base -> primary three-layer merge", func(t *testing.T) {
		defaults := model.DefaultSandboxControllerConfig()

		// Base layer: sets ext_proc, does not touch ignored labels.
		baseYml := `
sandboxExtProc:
  service: "base.example.com"
  port: 8080
`
		afterBase, err := applySandboxConfig(baseYml, defaults)
		if err != nil {
			t.Fatalf("applySandboxConfig (base) failed: %v", err)
		}

		// Primary layer: overrides ext_proc service only (port resets to 0).
		primaryYml := `
sandboxExtProc:
  service: "primary.example.com"
`
		got, err := applySandboxConfig(primaryYml, afterBase)
		if err != nil {
			t.Fatalf("applySandboxConfig (primary) failed: %v", err)
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "primary.example.com" {
			t.Errorf("service: expected primary.example.com, got %s", extProc.GetService())
		}
		// Port was set by base but primary's sandboxExtProc replaces the whole sub-message.
		if extProc.GetPort() != 0 {
			t.Errorf("port: expected 0 (reset by primary override), got %d", extProc.GetPort())
		}

		// Ignored labels were never touched by either override, so defaults survive.
		wantLabels := defaults.GetSandboxIgnoredLabels()
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("sandboxIgnoredLabels: expected defaults %v, got %v", wantLabels, gotLabels)
		}
	})
}

func TestApplySandboxConfig_EmptyOverride(t *testing.T) {
	cases := []struct {
		name string
		yml  string
	}{
		{"empty string", ""},
		{"empty object", "{}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defaults := model.DefaultSandboxControllerConfig()
			got, err := applySandboxConfig(tc.yml, defaults)
			if err != nil {
				t.Fatalf("applySandboxConfig failed: %v", err)
			}

			// Defaults should be fully preserved.
			wantLabels := defaults.GetSandboxIgnoredLabels()
			gotLabels := got.GetSandboxIgnoredLabels()
			if !reflect.DeepEqual(gotLabels, wantLabels) {
				t.Errorf("sandboxIgnoredLabels: expected %v, got %v", wantLabels, gotLabels)
			}

			// ext_proc should remain nil (not set in defaults or override).
			if got.GetSandboxExtProc() != nil {
				t.Errorf("expected nil sandboxExtProc, got %+v", got.GetSandboxExtProc())
			}
		})
	}
}

func TestApplySandboxConfig_NilDefaultConfig(t *testing.T) {
	t.Run("nil default produces valid output from override", func(t *testing.T) {
		yml := `
sandboxExtProc:
  service: "from-nil.example.com"
  port: 7070
sandboxIgnoredLabels:
  - "x"
  - "y"
`
		got, err := applySandboxConfig(yml, nil)
		if err != nil {
			t.Fatalf("applySandboxConfig failed: %v", err)
		}
		if got == nil || got.SandboxConfig == nil {
			t.Fatal("expected non-nil result")
		}

		extProc := got.GetSandboxExtProc()
		if extProc == nil {
			t.Fatal("expected sandboxExtProc to be set, got nil")
		}
		if extProc.GetService() != "from-nil.example.com" {
			t.Errorf("service: expected from-nil.example.com, got %s", extProc.GetService())
		}
		if extProc.GetPort() != 7070 {
			t.Errorf("port: expected 7070, got %d", extProc.GetPort())
		}

		wantLabels := []string{"x", "y"}
		gotLabels := got.GetSandboxIgnoredLabels()
		if !reflect.DeepEqual(gotLabels, wantLabels) {
			t.Errorf("sandboxIgnoredLabels: expected %v, got %v", wantLabels, gotLabels)
		}
	})

	t.Run("nil default with empty yaml produces empty config", func(t *testing.T) {
		got, err := applySandboxConfig("", nil)
		if err != nil {
			t.Fatalf("applySandboxConfig failed: %v", err)
		}
		if got == nil || got.SandboxConfig == nil {
			t.Fatal("expected non-nil result with valid SandboxConfig")
		}
		if got.GetSandboxExtProc() != nil {
			t.Errorf("expected nil sandboxExtProc, got %+v", got.GetSandboxExtProc())
		}
		if len(got.GetSandboxIgnoredLabels()) != 0 {
			t.Errorf("expected empty sandboxIgnoredLabels, got %v", got.GetSandboxIgnoredLabels())
		}
	})
}
