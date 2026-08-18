package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/albertloky/SBXR/internal/installation"
	"github.com/albertloky/SBXR/internal/ownerconsole"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	softwareubuntu "github.com/albertloky/SBXR/internal/softwarelifecycle/adapter/ubuntu"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

const packageQualificationRefusal = "RELEASE-STAGED-ONBOARDING-PACKAGE-REFUSED"

func runPackageQualification(ctx context.Context, arguments []string, output io.Writer) (resultErr error) {
	if len(arguments) != 5 || arguments[0] != "acceptance" || arguments[1] != "staged-onboarding" || arguments[2] != "--components" || arguments[3] == "" || arguments[4] != "--json" || output == nil {
		return errors.New("package qualification arguments refused")
	}
	metadata, err := readOwnPayloadMetadata()
	if err != nil {
		return err
	}
	componentArchive, err := readPackageQualificationComponents(arguments[3])
	if err != nil {
		return err
	}
	manifest, err := softwarelifecycle.ValidateComponentArchive(componentArchive, metadata.Architecture)
	if err != nil || manifest.Build != metadata.Build {
		return errors.New("package qualification components refused")
	}
	componentDigest := sha256.Sum256(componentArchive)
	componentSHA256 := hex.EncodeToString(componentDigest[:])
	return executePackageQualification(ctx, metadata, componentArchive, manifest, componentSHA256, output)
}

func executePackageQualification(ctx context.Context, metadata softwarelifecycle.PayloadMetadata, componentArchive []byte, manifest softwarelifecycle.ComponentManifest, componentSHA256 string, output io.Writer) (resultErr error) {
	root, err := os.MkdirTemp("", "sbxr-packaged-qualification-")
	if err != nil {
		return errors.New("package qualification unavailable")
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(root)) }()
	if os.Chmod(root, 0o700) != nil {
		return errors.New("package qualification unavailable")
	}
	xray, _, xrayOK := softwarelifecycle.QualificationComponent(componentArchive, metadata.Architecture, "xray")
	singBox, _, singBoxOK := softwarelifecycle.QualificationComponent(componentArchive, metadata.Architecture, "sing-box")
	xrayPath, singBoxPath := filepath.Join(root, "xray"), filepath.Join(root, "sing-box")
	if !xrayOK || !singBoxOK || os.WriteFile(xrayPath, xray, 0o700) != nil || os.WriteFile(singBoxPath, singBox, 0o700) != nil || softwareubuntu.ValidatePackageQualificationCores(ctx, xrayPath, singBoxPath, metadata) != nil {
		return errors.New("package qualification native validation refused")
	}
	controlledRoot := filepath.Join(root, "controlled")
	if os.Mkdir(controlledRoot, 0o700) != nil {
		return errors.New("package qualification unavailable")
	}
	load, err := installation.RunControlledInstallationAt(ctx, controlledRoot)
	if err != nil {
		return err
	}
	controlledCopies := map[string]string{}
	for _, name := range []string{"setup-rollback", "setup-recovery-required", "setup-restart"} {
		copyRoot := filepath.Join(root, name)
		if err := copyPackageQualificationRoot(controlledRoot, copyRoot); err != nil {
			return err
		}
		controlledCopies[name] = copyRoot
	}
	surfaces := map[string][]byte{}
	if err := runControlledCloudflareProfileSetupWithOptions(ctx, controlledRoot, load, controlledSetupOptions{confirm: true, singBoxValidator: packageSingBoxValidator{binary: singBoxPath}, scanSurface: func(name string, body []byte) error {
		surfaces[name] = append(surfaces[name], body...)
		return nil
	}}); err != nil {
		return err
	}
	installRestartRoot := filepath.Join(root, "install-restart")
	if os.Mkdir(installRestartRoot, 0o700) != nil || installation.QualifyControlledInstallationRestart(ctx, installRestartRoot) != nil {
		return errors.New("package qualification Installation restart refused")
	}
	for _, boundary := range []struct {
		name        string
		options     controlledSetupOptions
		wantJournal bool
	}{
		{name: "setup-rollback", options: controlledSetupOptions{confirm: false}},
		{name: "setup-recovery-required", options: controlledSetupOptions{confirm: true, failAction: systemchanges.CloudflareDNSCreate}, wantJournal: true},
	} {
		boundaryRoot := controlledCopies[boundary.name]
		if err := qualifyControlledCloudflareProfileSetupFailure(ctx, boundaryRoot, load, boundary.options, boundary.wantJournal); err != nil {
			return errors.New("package qualification " + boundary.name + " refused: " + err.Error())
		}
	}
	restartRoot := controlledCopies["setup-restart"]
	if qualifyControlledCloudflareProfileSetupRestart(ctx, restartRoot, load) != nil {
		return errors.New("package qualification setup restart refused")
	}
	if err := softwarelifecycle.QualifyControlledStagedOnboardingSurfaces(surfaces, []string{"transaction", "diagnostic", "http", "apply"}); err != nil {
		return err
	}
	markers := softwarelifecycle.ControlledStagedOnboardingSecretMarkers()
	markerText := make([]string, len(markers))
	for index, marker := range markers {
		markerText[index] = string(marker.Value)
	}
	if err := ownerconsole.QualifyControlledStagedOnboardingTerminalSecretSafe(ctx, markerText); err != nil {
		return err
	}
	if err := ownerconsole.QualifyControlledStagedOnboardingGuideText(ctx); err != nil {
		return err
	}
	evidence, err := softwarelifecycle.BuildPackageQualificationEvidence(metadata.Build, metadata.Architecture, manifest, componentSHA256)
	if err != nil || softwarelifecycle.ValidatePackageQualificationEvidence(evidence, metadata.Build, metadata.Architecture, manifest, componentSHA256) != nil {
		return errors.New("package qualification evidence refused")
	}
	_, err = output.Write(evidence)
	return err
}

func copyPackageQualificationRoot(source, target string) error {
	if os.Mkdir(target, 0o700) != nil {
		return errors.New("package qualification copy unavailable")
	}
	return filepath.Walk(source, func(name string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || name == source {
			return walkErr
		}
		relative, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, relative)
		if info.IsDir() {
			return os.Mkdir(destination, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return errors.New("package qualification copy refused")
		}
		body, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, body, info.Mode().Perm())
	})
}

type packageSingBoxValidator struct{ binary string }

func (validator packageSingBoxValidator) ValidateSingBox(ctx context.Context, document io.Reader) error {
	command := exec.CommandContext(ctx, validator.binary, "check", "-c", "/dev/stdin")
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.Stdin = document
	return command.Run()
}

func readPackageQualificationComponents(name string) ([]byte, error) {
	pathInfo, err := os.Lstat(name)
	if err != nil || !pathInfo.Mode().IsRegular() {
		return nil, errors.New("package qualification component input refused")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, errors.New("package qualification components unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > softwarelifecycle.MaxAssetBytes {
		return nil, errors.New("package qualification component input refused")
	}
	body, err := io.ReadAll(io.LimitReader(file, softwarelifecycle.MaxAssetBytes+1))
	if err != nil || int64(len(body)) != info.Size() {
		return nil, errors.New("package qualification components unavailable")
	}
	return body, nil
}
