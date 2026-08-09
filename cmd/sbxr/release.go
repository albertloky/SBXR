package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type versionReport struct {
	Build        softwarelifecycle.EmbeddedBuildIdentity `json:"build"`
	Architecture softwarelifecycle.Architecture          `json:"architecture"`
	StateSchema  uint64                                  `json:"state_schema"`
}

func readOwnVersion() (versionReport, error) {
	path, err := os.Executable()
	if err != nil {
		return versionReport{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return versionReport{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return versionReport{}, err
	}
	metadata, _, err := softwarelifecycle.ReadPayloadMetadata(file, info.Size())
	if err != nil {
		return versionReport{}, err
	}
	return versionReport{Build: metadata.Build, Architecture: metadata.Architecture, StateSchema: metadata.StateSchema}, nil
}

func writeVersion(output io.Writer, jsonOutput bool) error {
	report, err := readOwnVersion()
	if err != nil {
		return err
	}
	if jsonOutput {
		return json.NewEncoder(output).Encode(report)
	}
	_, err = fmt.Fprintf(output, "sbxr %s %s (%s linux/%s payload %s state-schema %d)\n", report.Build.Repository, report.Build.Tag, report.Build.Commit, report.Architecture, report.Build.PayloadSHA256, report.StateSchema)
	return err
}
