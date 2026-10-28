package host

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type accountMount struct {
	id, parent uint64
	path       string
	virtual    bool
}

func accountMountPath(raw string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' {
			if i+4 > len(raw) {
				return "", errors.New("mount escape")
			}
			switch raw[i+1 : i+4] {
			case "040":
				out.WriteByte(' ')
			case "011":
				out.WriteByte('\t')
			case "012":
				out.WriteByte('\n')
			case "134":
				out.WriteByte('\\')
			default:
				return "", errors.New("mount escape")
			}
			i += 3
		} else {
			if raw[i] < 32 || raw[i] == 127 {
				return "", errors.New("mount control")
			}
			out.WriteByte(raw[i])
		}
	}
	path := out.String()
	if !strings.HasPrefix(path, "/") || filepath.Clean(path) != path {
		return "", errors.New("mount path")
	}
	return path, nil
}
func accountMounts(body string) ([]accountMount, error) {
	if len(body) > 1<<20 || !utf8.ValidString(body) || !strings.HasSuffix(body, "\n") {
		return nil, errors.New("mount table")
	}
	var mounts []accountMount
	ids, paths := map[uint64]bool{}, map[string]bool{}
	hasRoot := false
	number := func(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, field := range f {
			if field == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) != sep+4 {
			return nil, errors.New("mount fields")
		}
		id, err := number(f[0])
		if err != nil || id == 0 || ids[id] {
			return nil, errors.New("mount id")
		}
		ids[id] = true
		parent, err := number(f[1])
		if err != nil {
			return nil, err
		}
		dev := strings.Split(f[2], ":")
		if len(dev) != 2 {
			return nil, errors.New("mount device")
		}
		for _, n := range dev {
			if _, err := number(n); err != nil {
				return nil, err
			}
		}
		if _, err := accountMountPath(f[3]); err != nil {
			return nil, err
		}
		path, err := accountMountPath(f[4])
		if err != nil {
			return nil, err
		}
		// Stacked mountpoints are ambiguous; never silently discard a mount.
		if paths[path] {
			return nil, errors.New("stacked mount")
		}
		paths[path] = true
		virtual := false
		switch f[sep+1] {
		case "proc", "sysfs", "cgroup", "cgroup2", "devpts":
			virtual = true
		}
		mounts = append(mounts, accountMount{id: id, parent: parent, path: path, virtual: virtual})
		hasRoot = hasRoot || path == "/" && !virtual
	}
	if !hasRoot {
		return nil, errors.New("missing data root")
	}
	// A hidden child of an overmounted ancestor must not prune visible data.
	// Require each pathname's nearest mount ancestor to be its actual parent.
	for _, mount := range mounts {
		if mount.path == "/" {
			if mount.parent != mount.id && ids[mount.parent] {
				return nil, errors.New("cyclic root mount")
			}
			continue
		}
		var parent *accountMount
		for i := range mounts {
			candidate := &mounts[i]
			if candidate.path != mount.path && accountWithin(mount.path, candidate.path) && (parent == nil || len(candidate.path) > len(parent.path)) {
				parent = candidate
			}
		}
		if parent == nil || mount.parent != parent.id {
			return nil, errors.New("ambiguous mount visibility")
		}
	}
	return mounts, nil
}
func accountWithin(path, parent string) bool {
	return path == parent || parent == "/" || strings.HasPrefix(path, parent+"/")
}
func accountLiteral(path string) string {
	return strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[", "]", "\\]").Replace(path)
}
func (a Adapter) accountFindArgs(m accountMount, all []accountMount, spec SetupSpec, uid *uint32, gid uint32) []string {
	args := []string{a.path(m.path), "-xdev"}
	var children []string
	for _, child := range all {
		if child.path != m.path && accountWithin(child.path, m.path) {
			if len(children) != 0 {
				children = append(children, "-o")
			}
			children = append(children, "-path", accountLiteral(a.path(child.path)))
		}
	}
	if len(children) != 0 {
		args = append(args, "(")
		args = append(args, children...)
		args = append(args, ")", "-prune", "-o")
	}
	args = append(args, "(")
	if uid != nil {
		args = append(args, "-uid", strconv.FormatUint(uint64(*uid), 10), "-o")
	}
	args = append(args, "-gid", strconv.FormatUint(uint64(gid), 10), ")")
	if uid != nil {
		for _, exception := range []struct {
			path    string
			subtree bool
		}{{spec.ConfigurationPath, false}, {spec.StatePath, true}} {
			// Nested data mounts beneath state do not inherit its exception.
			if accountWithin(exception.path, m.path) {
				pattern := accountLiteral(a.path(exception.path))
				args = append(args, "!", "-path", pattern)
				if exception.subtree {
					args = append(args, "!", "-path", pattern+"/*")
				}
			}
		}
	}
	return append(args, "-print", "-quit")
}

// Scope ownership to data mounts in one observed mount topology. Kernel
// metadata is excluded by filesystem type; tmpfs and unknown types are data.
// Each data mount is scanned independently, including beneath virtual mounts.
func (a Adapter) accountFiles(ctx context.Context, spec SetupSpec, uid *uint32, gid uint32) (bool, bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	run := func(name string, args ...string) (string, bool) {
		if ctx.Err() != nil {
			return "", false
		}
		body, err := boundedCommandOutput(exec.CommandContext(ctx, name, args...), false)
		return string(body), err == nil && ctx.Err() == nil && len(body) <= 1<<20
	}
	before, ok := run("cat", a.path("/proc/self/mountinfo"))
	if !ok {
		return false, false
	}
	mounts, err := accountMounts(before)
	if err != nil {
		return false, false
	}
	for _, mount := range mounts {
		if mount.virtual {
			continue
		}
		result, ok := run("find", a.accountFindArgs(mount, mounts, spec, uid, gid)...)
		if !ok {
			return false, false
		}
		if result != "" {
			return false, true
		}
	}
	after, ok := run("cat", a.path("/proc/self/mountinfo"))
	if !ok || after != before {
		return false, false
	}
	return true, true
}
