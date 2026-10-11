package nginx

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/metrics"
)

// ErrReloadRejected is what errors.Is matches when the running nginx did not
// take a reload. nginx -t passed and the files on disk are the ones the
// database describes, but the master refused them and kept its previous
// configuration, while `nginx -s reload` still exited 0. The master checks
// more than nginx -t does: a limit_req zone it already has may not change its
// key, and a port it is to listen on may be taken.
//
// Callers keep the files. Restoring the previous ones would undo a change
// nginx -t accepted and leave the database and the disk apart, and the
// restart that applies a refused reload would then load the undone state.
var ErrReloadRejected = errors.New("nginx kept its previous configuration")

// ReloadRejectedError is the error of a refused reload. Detail is the [emerg]
// line nginx logged for it without its timestamp, or "" when none was found.
// Error() leaves Detail out: handlers sort errors by words in their text, and
// nginx's line may hold one of them ("invalid ..."), which would turn this
// into a 400.
type ReloadRejectedError struct {
	Detail string
}

func (e *ReloadRejectedError) Error() string {
	const saved = "the change is saved, but the running nginx refused to load it and keeps its previous configuration"
	switch {
	case strings.Contains(e.Detail, "bind()"):
		return saved + "; a port it is to listen on is in use, so free that port or change the setting"
	case strings.Contains(e.Detail, "shared memory zone"), strings.Contains(e.Detail, "previously it used"):
		return saved + "; restart the nginx container to apply it"
	}
	return saved + "; nginx's reason is in the nginx container's log"
}

// Is makes errors.Is(err, ErrReloadRejected) match.
func (e *ReloadRejectedError) Is(target error) bool { return target == ErrReloadRejected }

// reloadProbe reads what confirming a reload needs from the nginx container.
// Tests substitute a fake.
type reloadProbe interface {
	// Children returns the pid of nginx's master process and the pids of its
	// children: the workers, and the cache manager and loader.
	Children(ctx context.Context) (master int, children map[int]bool, err error)
	// EmergSince returns the [emerg] lines nginx logged at or after since.
	EmergSince(ctx context.Context, since time.Time) ([]string, error)
}

// dockerReloadProbe reads the nginx container through docker.
type dockerReloadProbe struct {
	containerName string
	exec          healthExecutor // docker exec <container> ...
}

// nginxProcsScript prints the master's pid, then the /proc/<pid>/stat line of
// every process in the container. The fourth field of a stat line is the
// process's parent, so the master's children are found without matching any
// process name: the docker exec running this, the pgrep upForDeferredSteps
// runs and an operator's shell are not the master's children, whatever their
// command lines say.
const nginxProcsScript = "cat /var/run/nginx.pid && cat /proc/[0-9]*/stat 2>/dev/null; true"

func (p *dockerReloadProbe) Children(ctx context.Context) (int, map[int]bool, error) {
	out, err := p.exec.Exec(ctx, "sh", "-c", nginxProcsScript)
	if err != nil {
		return 0, nil, fmt.Errorf("read nginx processes: %w", err)
	}
	return parseNginxProcs(out)
}

// parseNginxProcs reads nginxProcsScript's output.
func parseNginxProcs(out string) (int, map[int]bool, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	master, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || master <= 0 {
		return 0, nil, fmt.Errorf("read nginx master pid: %.120q", lines[0])
	}
	children := make(map[int]bool)
	for _, line := range lines[1:] {
		// "<pid> (<name>) <state> <ppid> ...": the name may hold spaces and
		// parentheses, so the fields after it are counted from the last ")".
		end := strings.LastIndexByte(line, ')')
		if end < 0 {
			continue
		}
		head := strings.Fields(line[:end])
		tail := strings.Fields(line[end+1:])
		if len(head) == 0 || len(tail) < 2 {
			continue
		}
		pid, pidErr := strconv.Atoi(head[0])
		ppid, ppidErr := strconv.Atoi(tail[1])
		if pidErr != nil || ppidErr != nil {
			continue
		}
		if ppid == master {
			children[pid] = true
		}
	}
	return master, children, nil
}

func (p *dockerReloadProbe) EmergSince(ctx context.Context, since time.Time) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerExecTimeout)
	defer cancel()
	// nginx writes its error log to stderr (nginx/scripts/docker-entrypoint.sh),
	// which docker keeps as the container's log.
	cmd := exec.CommandContext(ctx, "docker", "logs", "--since", since.UTC().Format(time.RFC3339Nano), "--tail", "200", p.containerName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker logs: %w", err)
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "[emerg]") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// emergPrefix is what nginx puts before the message of a log line:
// "2026/10/11 09:00:00 [emerg] 1#1: ".
var emergPrefix = regexp.MustCompile(`^\S+ \S+ \[emerg\] \d+#\d+: (?:\*\d+ )?`)

// cleanEmergLine returns line without its timestamp and pid, cut to 300 bytes.
func cleanEmergLine(line string) string {
	msg := strings.TrimSpace(emergPrefix.ReplaceAllString(strings.TrimSpace(line), ""))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// reloadSnapshot is nginx's process tree just before a reload signal.
type reloadSnapshot struct {
	master   int
	children map[int]bool
}

// reloadLogChecks are the times after the signal at which confirmReload reads
// nginx's log while it waits, besides once at the end. A master that refuses
// a reload logs it at once, but one that takes it can need a while to start
// its new workers (about 0.6s for 60 WAF hosts on one CPU), and reading the
// log at every poll would run docker logs ten times a second.
var reloadLogChecks = []time.Duration{time.Second, 3 * time.Second}

// confirmReload waits for nginx to show what it did with the reload signalled
// at sentAt. A reload nginx takes starts new workers, children of the master
// that were not there before; one it refuses keeps the old ones and leaves an
// [emerg] line in its log. A refusal returns *ReloadRejectedError. When nginx
// shows neither within the wait, the reload is reported as taken, with a
// warning and the "unconfirmed" count: failing saves on that guess would, on
// slow hardware, report good saves as refused.
func (m *Manager) confirmReload(ctx context.Context, before reloadSnapshot, sentAt time.Time) error {
	start := time.Now()
	wait := m.reloadConfirmWait
	if wait <= 0 {
		wait = config.ReloadConfirmTimeout
	}
	every := m.reloadConfirmEvery
	if every <= 0 {
		every = config.ReloadConfirmPoll
	}
	deadline := start.Add(wait)
	checks := reloadLogChecks
	done := func(result string) {
		metrics.NginxReloadConfirmTotal.WithLabelValues(result).Inc()
		metrics.NginxReloadConfirmSeconds.Observe(time.Since(start).Seconds())
	}
	for {
		if master, children, err := m.reloadProbe.Children(ctx); err == nil {
			if master != before.master {
				done("accepted") // a new master read the files on disk
				return nil
			}
			for pid := range children {
				if !before.children[pid] {
					done("accepted")
					return nil
				}
			}
		}
		last := !time.Now().Before(deadline)
		readLog := last
		for len(checks) > 0 && time.Since(start) >= checks[0] {
			checks = checks[1:]
			readLog = true
		}
		if readLog {
			if lines, err := m.reloadProbe.EmergSince(ctx, sentAt); err == nil && len(lines) > 0 {
				done("rejected")
				detail := cleanEmergLine(lines[len(lines)-1])
				log.Printf("[NginxReload] nginx refused the reload and keeps its previous configuration: %s", detail)
				return &ReloadRejectedError{Detail: detail}
			}
		}
		if last {
			done("unconfirmed")
			log.Printf("[WARN] [NginxReload] nginx started no new worker within %v of the reload and logged no error; the reload is reported as applied", wait)
			return nil
		}
		select {
		case <-ctx.Done():
			done("unconfirmed")
			log.Printf("[WARN] [NginxReload] stopped waiting for nginx to take the reload: %v", ctx.Err())
			return nil
		case <-time.After(every):
		}
	}
}
