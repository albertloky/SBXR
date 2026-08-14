package ubuntu

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/albertloky/SBXR/internal/subscriptionserving"
)

var listenerPID = regexp.MustCompile(`pid=([0-9]+),`)

type commandRunner func(context.Context, string, ...string) (string, error)

type Inspector struct {
	run     commandRunner
	inspect func(subscriptionserving.RuntimeObservation) subscriptionserving.HealthResult
}

func New() Inspector {
	return Inspector{run: runCommand, inspect: subscriptionserving.InspectRuntime}
}

func (inspector Inspector) Inspect(ctx context.Context) subscriptionserving.HealthResult {
	if ctx == nil || inspector.run == nil || inspector.inspect == nil {
		return subscriptionserving.Result(errors.New("Subscription Serving runtime inspection unavailable"))
	}
	read := func(arguments ...string) (string, bool) {
		value, err := inspector.run(ctx, "/usr/bin/systemctl", arguments...)
		return strings.TrimSpace(value), err == nil
	}
	unitOutput, unitOK := read("cat", "sbxr-subscription.service")
	unitStart := strings.Index(unitOutput, "[Unit]")
	if unitStart < 0 {
		unitOK = false
	}
	unit := ""
	if unitOK {
		unit = unitOutput[unitStart:] + "\n"
	}
	user, userOK := read("show", "--property=User", "--value", "sbxr-subscription.service")
	group, groupOK := read("show", "--property=Group", "--value", "sbxr-subscription.service")
	active, activeOK := read("show", "--property=ActiveState", "--value", "sbxr-subscription.service")
	pidText, pidOK := read("show", "--property=MainPID", "--value", "sbxr-subscription.service")
	mainPID, pidErr := strconv.ParseUint(pidText, 10, 64)
	processIdentity, processErr := inspector.run(ctx, "/usr/bin/ps", "-o", "uid=", "-o", "gid=", "-p", pidText)
	processFields := strings.Fields(processIdentity)
	var processUID, processGID uint64
	var processUIDErr, processGIDErr error
	if len(processFields) == 2 {
		processUID, processUIDErr = strconv.ParseUint(processFields[0], 10, 32)
		processGID, processGIDErr = strconv.ParseUint(processFields[1], 10, 32)
	}
	listeners, listenerErr := inspector.run(ctx, "/usr/bin/ss", "-H", "-ltnp", "sport", "=", ":10443")
	listener, processPID, exactListener := parseListener(listeners)
	if !unitOK || !userOK || !groupOK || !activeOK || !pidOK || pidErr != nil || processErr != nil || len(processFields) != 2 || processUIDErr != nil || processGIDErr != nil || listenerErr != nil || !exactListener {
		return subscriptionserving.Result(errors.New("Subscription Serving runtime facts unavailable"))
	}
	return inspector.inspect(subscriptionserving.RuntimeObservation{Unit: unit, User: user, Group: group, ActiveState: active, MainPID: mainPID, ListenerPID: processPID, ProcessUID: uint32(processUID), ProcessGID: uint32(processGID), Listener: listener})
}

func parseListener(output string) (netip.AddrPort, uint64, bool) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 1 {
		return netip.AddrPort{}, 0, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "LISTEN" {
		return netip.AddrPort{}, 0, false
	}
	listener, err := netip.ParseAddrPort(fields[3])
	match := listenerPID.FindStringSubmatch(lines[0])
	if err != nil || len(match) != 2 {
		return netip.AddrPort{}, 0, false
	}
	pid, err := strconv.ParseUint(match[1], 10, 64)
	return listener, pid, err == nil
}

func runCommand(ctx context.Context, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	output, err := command.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := command.Start(); err != nil {
		return "", err
	}
	body, readErr := io.ReadAll(io.LimitReader(output, (1<<20)+1))
	if len(body) > 1<<20 {
		_ = command.Process.Kill()
		_ = command.Wait()
		return "", errors.New("runtime command output is too large")
	}
	waitErr := command.Wait()
	if readErr != nil || waitErr != nil {
		return "", errors.New("runtime command failed")
	}
	return string(body), nil
}
