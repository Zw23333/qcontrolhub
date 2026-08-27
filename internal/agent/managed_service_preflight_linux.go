//go:build linux

package agent

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
)

var managedCorePreflightSystemdRunPath = "/usr/bin/systemd-run"

// runManagedCorePreflight asks systemd to run the real core validation command
// as the same unprivileged account used by the managed service. QAgent itself
// intentionally lacks CAP_SETUID/CAP_SETGID, so a direct credential change
// would fail under the hardened qagent.service capability boundary.
func runManagedCorePreflight(ctx context.Context, manager *ServiceManager, spec EngineSpec, arguments ...string) (string, error) {
	if manager.Kind() == ServiceManagerOpenRC {
		// OpenRC has no transient-unit equivalent. The regular protected import
		// validation and atomic rollback remain in force on those nodes.
		return "", nil
	}
	if err := validatePrivilegedExecutable(managedCorePreflightSystemdRunPath); err != nil {
		return "", err
	}
	if err := validatePrivilegedExecutable(spec.Binary); err != nil {
		return "", err
	}
	runnerArguments := []string{
		"--pipe", "--wait", "--collect", "--quiet", "--service-type=exec",
		"--property=User=" + managedCoreServiceGroup,
		"--property=Group=" + managedCoreServiceGroup,
		"--property=WorkingDirectory=" + filepath.Dir(spec.ConfigPath),
		"--property=UMask=0027", "--property=NoNewPrivileges=yes",
		"--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
		"--property=ProtectSystem=strict", "--property=ProtectHome=yes",
		"--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
		"--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
	}
	if spec.commandEnv != "" {
		runnerArguments = append(runnerArguments, "--setenv="+spec.commandEnv)
	}
	runnerArguments = append(runnerArguments, "--", spec.Binary)
	runnerArguments = append(runnerArguments, arguments...)

	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(commandContext, managedCorePreflightSystemdRunPath, runnerArguments...)
	command.Env = commandEnvironment("")
	configureCommand(command)
	output := &boundedOutput{limit: 64 << 10, onLimit: cancel}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	value := strings.TrimSpace(strings.ToValidUTF8(output.String(), "�"))
	if output.Truncated() {
		value += "\n… process terminated after exceeding the 64 KiB output limit"
		if ctx.Err() == nil {
			err = errors.New("command output limit exceeded")
		}
	}
	if ctx.Err() != nil {
		return value, ctx.Err()
	}
	return value, err
}
