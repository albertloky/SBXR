// Package filesystem atomically activates Subscription Publication artifact sets.
package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	subscriptionpublication "github.com/albertloky/SBXR/internal/subscriptionpublication"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const subscriptionDirectory = "var/lib/sbxr/subscriptions"
const servingConfigurationName = "serving.json"

type Executor struct {
	uid, gid int
	prove    func(context.Context, string) error
	prior    *priorAuthorization
}

type PublishedFacts struct {
	Revision      uint64
	StateSHA256   string
	Compatibility subscriptionpublication.CompatibilityDefinition
	Serving       systemchanges.HealthStatus
}

type priorAuthorization struct {
	mu    sync.Mutex
	token string
}

func New(prove func(context.Context, string) error) (Executor, error) {
	if prove == nil {
		return Executor{}, errors.New("Subscription Serving health proof unavailable")
	}
	return Executor{uid: 0, gid: 0, prove: prove, prior: &priorAuthorization{}}, nil
}

// NewAt supplies controlled ownership and health proof for Seam Verification.
func NewAt(uid, gid int, prove func(context.Context, string) error) Executor {
	return Executor{uid: uid, gid: gid, prove: prove}
}

func NewForFreshInstallation(prove func(context.Context, string) error) (Executor, error) {
	if prove == nil {
		return Executor{}, errors.New("Subscription Serving health proof unavailable")
	}
	return Executor{uid: 0, gid: 0, prove: prove, prior: &priorAuthorization{}}, nil
}

type snapshot struct {
	Target string `json:"target,omitempty"`
}

type store struct {
	root     *os.Root
	uid, gid int
}

func (executor Executor) CaptureRollback(root string, write func(io.Reader) error) error {
	if write == nil {
		return errors.New("subscription rollback capture unavailable")
	}
	storage, err := openStore(root, false, executor.uid, executor.gid)
	if errors.Is(err, os.ErrNotExist) {
		encoded, _ := json.Marshal(snapshot{})
		return write(bytes.NewReader(encoded))
	}
	if err != nil {
		return errors.New("active subscription pointer is unprovable")
	}
	defer storage.root.Close()
	target, err := storage.current()
	if err != nil {
		return err
	}
	if target != "" && executor.prior != nil {
		configuration, readErr := storage.readConfiguration("current")
		authorization, parseErr := parseServingAuthorization(configuration)
		if readErr != nil || parseErr != nil {
			return errors.New("prior Subscription Serving authorization is unprovable")
		}
		executor.prior.mu.Lock()
		executor.prior.token = authorization.Token
		executor.prior.mu.Unlock()
	}
	encoded, _ := json.Marshal(snapshot{Target: target})
	return write(bytes.NewReader(encoded))
}

func (executor Executor) Activate(root, prepared string, binding systemchanges.StateTransactionBinding, expectedSHA256 string, timeout time.Duration) (systemchanges.StepEvidence, error) {
	if timeout <= 0 {
		return systemchanges.StepEvidence{}, errors.New("subscription activation timeout is invalid")
	}
	bundle, err := os.ReadFile(path.Join(prepared, "subscriptions.bundle"))
	if err != nil {
		return systemchanges.StepEvidence{}, errors.New("complete prepared subscription artifact set unavailable")
	}
	set, err := subscriptionpublication.DecodePreparedArtifactSet(bytes.NewReader(bundle))
	if err != nil || !set.AgreesWith(binding) || subscriptionpublication.BundleSHA256(bundle) != expectedSHA256 {
		return systemchanges.StepEvidence{}, errors.New("prepared subscription artifact set does not agree with State")
	}
	configuration, err := readPreparedConfiguration(prepared, executor.uid)
	if err != nil {
		return systemchanges.StepEvidence{}, errors.New("prepared Subscription Serving configuration is unavailable")
	}
	storage, err := openStore(root, true, executor.uid, executor.gid)
	if err != nil {
		return systemchanges.StepEvidence{}, errors.New("subscription serving directory unavailable")
	}
	defer storage.root.Close()
	target := "sets/" + set.GenerationID()
	prior, err := storage.current()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if err := storage.writeSet(target, set, configuration); err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if prior == "" {
		if err := storage.setServingMode(target, true); err != nil {
			return systemchanges.StepEvidence{}, errors.New("subscription candidate permission failed")
		}
		if err := storage.root.Rename(target, "current"); err != nil {
			_ = storage.setServingMode(target, false)
			return systemchanges.StepEvidence{}, errors.New("subscription activation failed")
		}
	} else {
		if _, err := storage.root.Lstat(prior); !errors.Is(err, os.ErrNotExist) || storage.root.Rename(target, prior) != nil {
			return systemchanges.StepEvidence{}, errors.New("prior subscription staging path is unavailable")
		}
		if err := storage.setServingMode(prior, true); err != nil || exchangeDirectories(storage.root, "current", prior) != nil {
			_ = storage.setServingMode(prior, false)
			return systemchanges.StepEvidence{}, errors.New("subscription activation failed")
		}
		if err := storage.setServingMode(prior, false); err != nil {
			return systemchanges.StepEvidence{}, errors.New("prior subscription generation could not be isolated")
		}
	}
	syncNames := []string{"current", "sets", "."}
	if prior != "" {
		syncNames = append([]string{prior}, syncNames...)
	}
	if err := syncNamespace(storage.root, syncNames...); err != nil {
		return systemchanges.StepEvidence{}, errors.New("subscription activation durability failed")
	}
	digest := sha256.Sum256([]byte(target))
	return systemchanges.StepEvidence{Code: "subscription-artifacts-activated", SHA256: hex.EncodeToString(digest[:])}, nil
}

func readPreparedConfiguration(prepared string, uid int) ([]byte, error) {
	name := path.Join(prepared, "subscription.json")
	info, err := os.Lstat(name)
	stat, ok := fileStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Type() != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 64<<10 || stat.Uid != uint32(uid) {
		return nil, errors.New("unsafe prepared Subscription Serving configuration")
	}
	configuration, err := os.ReadFile(name)
	if err != nil || !json.Valid(configuration) {
		return nil, errors.New("invalid prepared Subscription Serving configuration")
	}
	return configuration, nil
}

func (executor Executor) Reverse(root string, source io.Reader, _ time.Duration) (systemchanges.StepEvidence, error) {
	prior, err := decodeSnapshot(source)
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	storage, err := openStore(root, false, executor.uid, executor.gid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && prior.Target == "" {
			return systemchanges.StepEvidence{Code: "subscription-artifacts-restored", SHA256: emptyTargetSHA()}, nil
		}
		return systemchanges.StepEvidence{}, errors.New("subscription serving directory unavailable")
	}
	defer storage.root.Close()
	current, err := storage.current()
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	if current == prior.Target {
		if err := storage.removeOtherSets(""); err != nil {
			return systemchanges.StepEvidence{}, errors.New("subscription candidate cleanup failed")
		}
		if current != "" {
			if err := syncNamespace(storage.root, "current", "sets", "."); err != nil {
				return systemchanges.StepEvidence{}, errors.New("subscription rollback durability failed")
			}
		} else if err := syncNamespace(storage.root, "sets", "."); err != nil {
			return systemchanges.StepEvidence{}, errors.New("subscription rollback durability failed")
		}
		digest := sha256.Sum256([]byte(prior.Target))
		return systemchanges.StepEvidence{Code: "subscription-artifacts-restored", SHA256: hex.EncodeToString(digest[:])}, nil
	}
	if prior.Target != "" {
		if _, err := storage.readSet(prior.Target, 0o700); err != nil {
			if _, transientErr := storage.readSet(prior.Target, 0o755); transientErr != nil {
				return systemchanges.StepEvidence{}, errors.New("prior subscription artifact set is unprovable")
			}
		}
	}
	if prior.Target != "" {
		if err := storage.setServingMode(prior.Target, true); err != nil {
			return systemchanges.StepEvidence{}, errors.New("prior subscription generation could not be restored")
		}
		if err := exchangeDirectories(storage.root, "current", prior.Target); err != nil {
			_ = storage.setServingMode(prior.Target, false)
			return systemchanges.StepEvidence{}, errors.New("prior subscription restore failed")
		}
		if err := storage.setServingMode(prior.Target, false); err != nil {
			return systemchanges.StepEvidence{}, errors.New("subscription candidate could not be isolated")
		}
	} else if current != "" {
		if err := storage.root.Rename("current", current); err != nil || storage.root.Chmod(current, 0o700) != nil {
			return systemchanges.StepEvidence{}, errors.New("fresh subscription activation could not be reversed")
		}
	}
	if err := storage.removeOtherSets(""); err != nil {
		return systemchanges.StepEvidence{}, errors.New("subscription candidate cleanup failed")
	}
	if err := syncNamespace(storage.root, ".", "sets"); err != nil {
		return systemchanges.StepEvidence{}, errors.New("subscription rollback durability failed")
	}
	if prior.Target != "" {
		if err := syncRootDirectory(storage.root, "current"); err != nil {
			return systemchanges.StepEvidence{}, errors.New("subscription rollback durability failed")
		}
	}
	digest := sha256.Sum256([]byte(prior.Target))
	return systemchanges.StepEvidence{Code: "subscription-artifacts-restored", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (executor Executor) Inspect(root string, source io.Reader, _ time.Duration) (systemchanges.StepEffect, error) {
	prior, err := decodeSnapshot(source)
	if err != nil {
		return "", err
	}
	storage, err := openStore(root, false, executor.uid, executor.gid)
	if errors.Is(err, os.ErrNotExist) && prior.Target == "" {
		return systemchanges.StepEffectAbsent, nil
	}
	if err != nil {
		return "", err
	}
	defer storage.root.Close()
	current, err := storage.current()
	if err != nil {
		return "", err
	}
	other, err := storage.hasOtherSet(prior.Target)
	if err != nil {
		return "", err
	}
	if current == prior.Target && !other {
		return systemchanges.StepEffectAbsent, nil
	}
	return systemchanges.StepEffectPresent, nil
}

func (executor Executor) Check(root, code string, binding systemchanges.StateTransactionBinding, expectedSHA256 string, timeout time.Duration) (systemchanges.HealthStatus, error) {
	storage, err := openStore(root, false, executor.uid, executor.gid)
	if err != nil {
		return systemchanges.Failed, errors.New("active subscription artifact set is unprovable")
	}
	defer storage.root.Close()
	current, err := storage.current()
	if err != nil || current == "" {
		return systemchanges.Failed, errors.New("active subscription artifact set is unprovable")
	}
	set, err := storage.readSet("current", 0o755)
	bundle, bundleErr := set.Bundle()
	if err != nil || bundleErr != nil || !set.AgreesWith(binding) || subscriptionpublication.BundleSHA256(bundle) != expectedSHA256 {
		return systemchanges.Failed, errors.New("active subscription artifact set does not agree with State")
	}
	if code == "SUBSCRIPTION-PUBLICATION-SERVING-AGREEMENT" {
		if executor.prove == nil {
			return systemchanges.Unknown, errors.New("Subscription Serving health proof unavailable")
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := executor.prove(ctx, set.SelectedAddress()); err != nil {
			return systemchanges.Failed, errors.New("Subscription Serving health proof failed")
		}
		if executor.prior != nil {
			configuration, readErr := storage.readConfiguration("current")
			current, parseErr := parseServingAuthorization(configuration)
			executor.prior.mu.Lock()
			prior := executor.prior.token
			executor.prior.mu.Unlock()
			if readErr != nil || parseErr != nil || proveServingAuthorization(ctx, set.SelectedAddress(), current, prior) != nil {
				return systemchanges.Failed, errors.New("Subscription Serving authorization proof failed")
			}
		}
	}
	return systemchanges.Healthy, nil
}

// ObserveCurrent proves the active immutable publication and its Serving route without changing either.
func (executor Executor) ObserveCurrent(root string, timeout time.Duration) (PublishedFacts, error) {
	if timeout <= 0 {
		return PublishedFacts{}, errors.New("Subscription Publication observation unavailable")
	}
	storage, err := openStore(root, false, executor.uid, executor.gid)
	if errors.Is(err, os.ErrNotExist) {
		return PublishedFacts{Serving: systemchanges.Unknown}, nil
	}
	if err != nil {
		return PublishedFacts{}, errors.New("active subscription artifact set is unprovable")
	}
	defer storage.root.Close()
	current, err := storage.current()
	if err != nil {
		return PublishedFacts{}, errors.New("active subscription artifact set is unprovable")
	}
	if current == "" {
		return PublishedFacts{Serving: systemchanges.Unknown}, nil
	}
	set, err := storage.readSet("current", 0o755)
	if err != nil {
		return PublishedFacts{}, errors.New("active subscription artifact set is unprovable")
	}
	revision, stateSHA256, compatibility := set.PublicationFacts()
	result := PublishedFacts{Revision: revision, StateSHA256: stateSHA256, Compatibility: compatibility, Serving: systemchanges.Unknown}
	if executor.prove == nil {
		return result, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := executor.prove(ctx, set.SelectedAddress()); err != nil {
		result.Serving = systemchanges.Failed
		return result, nil
	}
	result.Serving = systemchanges.Healthy
	return result, nil
}

type servingAuthorization struct {
	Token      string `json:"token"`
	ListenPort uint16 `json:"listen_port"`
}

func parseServingAuthorization(configuration []byte) (servingAuthorization, error) {
	var authorization servingAuthorization
	if json.Unmarshal(configuration, &authorization) != nil || authorization.Token == "" || authorization.ListenPort == 0 {
		return servingAuthorization{}, errors.New("Subscription Serving authorization unavailable")
	}
	return authorization, nil
}

func proveServingAuthorization(ctx context.Context, address string, current servingAuthorization, prior string) error {
	request := func(token string) (*http.Response, error) {
		url := "https://" + net.JoinHostPort(address, strconv.Itoa(int(current.ListenPort))) + "/s/" + token + "/base64"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		return http.DefaultClient.Do(req)
	}
	response, err := request(current.Token)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("candidate Subscription authorization unavailable")
	}
	if prior == "" || prior == current.Token {
		return nil
	}
	response, err = request(prior)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 11))
	if err != nil || response.StatusCode != http.StatusNotFound || string(body) != "not found\n" {
		return errors.New("prior Subscription authorization remains active")
	}
	return nil
}

func (executor Executor) Cleanup(root string) error {
	storage, err := openStore(root, false, executor.uid, executor.gid)
	if err != nil {
		return err
	}
	defer storage.root.Close()
	current, err := storage.current()
	if err != nil || current == "" {
		return errors.New("active subscription pointer is unprovable")
	}
	return storage.removeOtherSets(current)
}

func openStore(host string, create bool, uid, gid int) (*store, error) {
	root, err := os.OpenRoot(host)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*store, error) { root.Close(); return nil, err }
	for _, directory := range []string{"var", "var/lib", "var/lib/sbxr"} {
		info, statErr := root.Lstat(directory)
		if errors.Is(statErr, os.ErrNotExist) && !create {
			return fail(os.ErrNotExist)
		}
		if errors.Is(statErr, os.ErrNotExist) && create {
			if err := root.Mkdir(directory, 0o755); err != nil {
				return fail(err)
			}
			info, statErr = root.Lstat(directory)
		}
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fail(errors.New("unsafe Subscription Publication parent directory"))
		}
	}
	for _, wanted := range []struct {
		name string
		mode fs.FileMode
	}{{subscriptionDirectory, 0o755}, {subscriptionDirectory + "/sets", 0o700}} {
		info, statErr := root.Lstat(wanted.name)
		if errors.Is(statErr, os.ErrNotExist) && create {
			if err := root.Mkdir(wanted.name, wanted.mode); err != nil || root.Chown(wanted.name, uid, gid) != nil {
				return fail(errors.New("subscription directory setup failed"))
			}
			info, statErr = root.Lstat(wanted.name)
		}
		if errors.Is(statErr, os.ErrNotExist) && !create {
			return fail(os.ErrNotExist)
		}
		stat, ok := fileStat(info)
		if statErr != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != wanted.mode || stat.Uid != uint32(uid) || stat.Gid != uint32(gid) {
			return fail(errors.New("unsafe Subscription Publication directory"))
		}
	}
	subscriptions, err := root.OpenRoot(subscriptionDirectory)
	root.Close()
	if err != nil {
		return nil, err
	}
	return &store{root: subscriptions, uid: uid, gid: gid}, nil
}

func (storage *store) current() (string, error) {
	_, err := storage.root.Lstat("current")
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", errors.New("active subscription pointer is unprovable")
	}
	set, err := storage.readSet("current", 0o755)
	if err != nil {
		return "", errors.New("active subscription artifact set is unprovable")
	}
	return "sets/" + set.GenerationID(), nil
}

func (storage *store) readSet(target string, mode fs.FileMode) (subscriptionpublication.PreparedArtifactSet, error) {
	if target != "current" && !safeTarget(target) {
		return subscriptionpublication.PreparedArtifactSet{}, errors.New("unsafe subscription generation")
	}
	info, err := storage.root.Lstat(target)
	stat, ok := fileStat(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || stat.Uid != uint32(storage.uid) || stat.Gid != uint32(storage.gid) {
		return subscriptionpublication.PreparedArtifactSet{}, errors.New("subscription generation directory is unsafe")
	}
	entries, err := fs.ReadDir(storage.root.FS(), target)
	if err != nil || len(entries) != 9 {
		return subscriptionpublication.PreparedArtifactSet{}, errors.New("active subscription artifact set is incomplete")
	}
	files := make([]subscriptionpublication.ArtifactFile, 0, len(entries))
	for _, artifactName := range subscriptionpublication.Names() {
		name := path.Join(target, artifactName)
		info, err := storage.root.Lstat(name)
		stat, ok := fileStat(info)
		if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Type() != 0 || info.Mode().Perm() != 0o644 || info.Size() > 4<<20 || stat.Uid != uint32(storage.uid) || stat.Gid != uint32(storage.gid) {
			return subscriptionpublication.PreparedArtifactSet{}, errors.New("subscription artifact is unsafe")
		}
		body, err := storage.root.ReadFile(name)
		if err != nil {
			return subscriptionpublication.PreparedArtifactSet{}, errors.New("subscription artifact is unavailable")
		}
		files = append(files, subscriptionpublication.ArtifactFile{Name: artifactName, Body: body})
	}
	if _, err := storage.readConfiguration(target); err != nil {
		return subscriptionpublication.PreparedArtifactSet{}, err
	}
	return subscriptionpublication.DecodePreparedArtifactFiles(files)
}

func (storage *store) readConfiguration(target string) ([]byte, error) {
	name := path.Join(target, servingConfigurationName)
	info, err := storage.root.Lstat(name)
	stat, ok := fileStat(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Type() != 0 || info.Mode().Perm() != 0o644 || info.Size() <= 0 || info.Size() > 64<<10 || stat.Uid != uint32(storage.uid) || stat.Gid != uint32(storage.gid) {
		return nil, errors.New("Subscription Serving configuration is unsafe")
	}
	configuration, err := storage.root.ReadFile(name)
	if err != nil || !json.Valid(configuration) {
		return nil, errors.New("Subscription Serving configuration is unavailable")
	}
	return configuration, nil
}

func (storage *store) writeSet(target string, set subscriptionpublication.PreparedArtifactSet, configuration []byte) error {
	if info, err := storage.root.Lstat(target); err == nil {
		if !info.IsDir() {
			return errors.New("subscription generation identity conflicts")
		}
		existing, readErr := storage.readSet(target, info.Mode().Perm())
		existingBundle, existingErr := existing.Bundle()
		existingConfiguration, configurationErr := storage.readConfiguration(target)
		candidateBundle, candidateErr := set.Bundle()
		if readErr != nil || existingErr != nil || configurationErr != nil || candidateErr != nil || !bytes.Equal(existingBundle, candidateBundle) || !bytes.Equal(existingConfiguration, configuration) {
			return errors.New("subscription generation identity conflicts")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := target + ".preparing"
	if _, err := storage.root.Lstat(temporary); !errors.Is(err, os.ErrNotExist) {
		return errors.New("unresolved subscription generation preparation")
	}
	if err := storage.root.Mkdir(temporary, 0o700); err != nil || storage.root.Chown(temporary, storage.uid, storage.gid) != nil {
		return errors.New("subscription generation preparation failed")
	}
	defer storage.root.RemoveAll(temporary)
	for _, artifact := range set.Files() {
		name := path.Join(temporary, artifact.Name)
		file, err := storage.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return errors.New("subscription artifact write failed")
		}
		_, writeErr := file.Write(artifact.Body)
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil || storage.root.Chown(name, storage.uid, storage.gid) != nil {
			return errors.New("subscription artifact write failed")
		}
	}
	configurationPath := path.Join(temporary, servingConfigurationName)
	configurationFile, err := storage.root.OpenFile(configurationPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errors.New("Subscription Serving configuration write failed")
	}
	_, writeErr := configurationFile.Write(configuration)
	syncErr := configurationFile.Sync()
	closeErr := configurationFile.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || storage.root.Chown(configurationPath, storage.uid, storage.gid) != nil {
		return errors.New("Subscription Serving configuration write failed")
	}
	if err := syncRootDirectory(storage.root, temporary); err != nil || storage.root.Rename(temporary, target) != nil {
		return errors.New("subscription generation activation failed")
	}
	return syncRootDirectory(storage.root, "sets")
}

func (storage *store) setServingMode(target string, active bool) error {
	directoryMode := fs.FileMode(0o700)
	if active {
		directoryMode = 0o755
	}
	return storage.root.Chmod(target, directoryMode)
}

func (storage *store) hasOtherSet(keep string) (bool, error) {
	entries, err := fs.ReadDir(storage.root.FS(), "sets")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		target := "sets/" + entry.Name()
		if target == keep {
			set, readErr := storage.readSet(target, 0o700)
			if readErr != nil || "sets/"+set.GenerationID() != keep {
				return true, nil
			}
			continue
		}
		return true, nil
	}
	return false, nil
}

func (storage *store) removeOtherSets(keep string) error {
	entries, err := fs.ReadDir(storage.root.FS(), "sets")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		target := "sets/" + entry.Name()
		baseTarget := strings.TrimSuffix(target, ".preparing")
		if target == keep {
			continue
		}
		if !safeTarget(baseTarget) || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unsafe subscription generation")
		}
		if err := storage.root.RemoveAll(target); err != nil {
			return err
		}
	}
	return syncRootDirectory(storage.root, "sets")
}

func safeTarget(target string) bool {
	suffix, ok := strings.CutPrefix(target, "sets/revision-")
	if !ok || len(suffix) != 33 || suffix[20] != '-' {
		return false
	}
	for _, character := range suffix {
		if character == '-' || character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func decodeSnapshot(source io.Reader) (snapshot, error) {
	var prior snapshot
	if source == nil || json.NewDecoder(io.LimitReader(source, 4096)).Decode(&prior) != nil || prior.Target != "" && !safeTarget(prior.Target) {
		return snapshot{}, errors.New("prior subscription pointer is invalid")
	}
	return prior, nil
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func syncRootDirectory(root *os.Root, name string) error {
	directory, err := root.Open(name)
	if err != nil {
		return err
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncNamespace(root *os.Root, names ...string) error {
	for _, name := range names {
		if err := syncRootDirectory(root, name); err != nil {
			return err
		}
	}
	return nil
}

func emptyTargetSHA() string {
	digest := sha256.Sum256(nil)
	return hex.EncodeToString(digest[:])
}
