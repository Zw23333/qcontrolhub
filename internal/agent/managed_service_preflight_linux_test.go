//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qimaoww/qcontrolhub/internal/core"
)

func TestManagedServicePreflightReportsServiceUserDependencyFailure(t *testing.T) {
	requireAgentRoot(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	argumentsPath := filepath.Join(root, "arguments")
	runner := filepath.Join(root, "systemd-run")
	runnerScript := fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %q
printf 'FATAL[0000] create service: read key: open /etc/sing-box/certs/privkey.pem: permission denied\n' >&2
exit 1
`, argumentsPath)
	if err := os.WriteFile(runner, []byte(runnerScript), 0o700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "sing-box")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	configDirectory := filepath.Join(root, "config")
	if err := os.Mkdir(configDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDirectory, "config.json")
	if err := os.WriteFile(configPath, []byte(`{"inbounds":[],"outbounds":[]}`), 0o640); err != nil {
		t.Fatal(err)
	}

	previousRunner := managedCorePreflightSystemdRunPath
	managedCorePreflightSystemdRunPath = runner
	t.Cleanup(func() { managedCorePreflightSystemdRunPath = previousRunner })
	err := validateManagedServiceConfigurationForServiceUser(
		context.Background(), core.EngineSingBox,
		EngineSpec{Binary: binary, ConfigPath: configPath, Service: "qagent-sing-box.service"},
		defaultSystemdServiceManager(),
	)
	if err == nil {
		t.Fatal("unreadable external private key preflight unexpectedly succeeded")
	}
	message := err.Error()
	for _, expected := range []string{
		"managed sing-box service user qcontrolhub-core",
		"before service cutover",
		"/etc/sing-box/certs/privkey.pem: permission denied",
		"grant that user read access",
		"traverse access to its parent directories",
	} {
		if !strings.Contains(message, expected) {
			t.Fatalf("preflight error %q does not contain %q", message, expected)
		}
	}
	arguments, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	argumentText := string(arguments)
	for _, expected := range []string{
		"--property=User=qcontrolhub-core",
		"--property=Group=qcontrolhub-core",
		"--property=NoNewPrivileges=yes",
		"--property=ProtectSystem=strict",
		binary,
		"check",
		"-c",
		configPath,
	} {
		if !strings.Contains(argumentText, expected+"\n") {
			t.Fatalf("systemd-run arguments %q do not contain %q", argumentText, expected)
		}
	}
}

func TestManagedServicePreflightSkipsOpenRCTransientCheck(t *testing.T) {
	output, err := runManagedCorePreflight(
		context.Background(),
		&ServiceManager{kind: ServiceManagerOpenRC},
		EngineSpec{Binary: "/missing", ConfigPath: "/missing"},
		"check", "-c", "/missing",
	)
	if err != nil || output != "" {
		t.Fatalf("OpenRC preflight = %q, %v", output, err)
	}
}
