// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentio-chart-sync <prepare|apply|verify> [flags]")
		return 2
	}
	switch args[0] {
	case "prepare":
		if err := runPrepare(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "prepare Agentio release chart: %v\n", err)
			return 1
		}
		return 0
	case "apply":
		if err := runApply(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "apply OpenKruise integration bundle: %v\n", err)
			return 1
		}
		return 0
	case "verify":
		if err := runVerify(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "verify OpenKruise integration bundle: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
		return 2
	}
}

func runPrepare(args []string) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	chart := flags.String("chart", "", "standalone Agentio chart directory")
	version := flags.String("version", "", "Agentio release version")
	sourceRepository := flags.String("source-repository", "openkruise/agentio", "GitHub source repository")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *chart == "" || *version == "" {
		return errors.New("--chart and --version are required")
	}
	return PrepareReleaseChart(*chart, *version, *sourceRepository)
}

func runApply(args []string) error {
	flags := flag.NewFlagSet("apply", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	bundle := flags.String("bundle", "", "prepared OpenKruise integration bundle directory")
	managerChart := flags.String("manager-chart", "", "sandbox-manager chart directory")
	controllerChart := flags.String("controller-chart", "", "sandbox-controller chart directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundle == "" || *managerChart == "" {
		return errors.New("--bundle and --manager-chart are required")
	}
	if err := Export(filepath.Join(*bundle, "sandbox-manager"), *managerChart); err != nil {
		return fmt.Errorf("sync sandbox-manager integration: %w", err)
	}
	if *controllerChart != "" {
		if err := ExportSandboxController(filepath.Join(*bundle, "sandbox-controller"), *controllerChart); err != nil {
			return fmt.Errorf("sync sandbox-controller integration: %w", err)
		}
	}
	return nil
}

func runVerify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	bundle := flags.String("bundle", "", "prepared OpenKruise integration bundle directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *bundle == "" {
		return errors.New("--bundle is required")
	}
	return VerifyIntegrationBundle(*bundle)
}
