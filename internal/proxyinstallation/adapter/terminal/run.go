// Package terminal presents Proxy Installation through the numbered V3 menu.
package terminal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/albertloky/SBXR/internal/proxyinstallation"
)

var errInputTooLong = errors.New("input line too long")

// Run owns one numbered-menu session.
func Run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer, installation proxyinstallation.Interface) int {
	if len(arguments) != 0 || input == nil || output == nil || errorOutput == nil || installation == nil {
		if errorOutput != nil {
			_, _ = io.WriteString(errorOutput, "SBXR accepts no arguments.\nRun: sudo sbxr\n")
		}
		return 1
	}
	reader := bufio.NewReader(input)
	current := installation.Review(ctx, proxyinstallation.StatusAction)
	latest := current.Result
	for {
		if writeFrame(output, current, latest) != nil {
			return 1
		}
		line, err := readLine(reader)
		if errors.Is(err, errInputTooLong) {
			if _, err := io.WriteString(output, "Enter one of the displayed numbers.\n"); err != nil {
				return 1
			}
			continue
		}
		if err == io.EOF && line == "" {
			return 0
		}
		if err != nil && err != io.EOF {
			return 1
		}
		if line == "0" {
			return 0
		}
		number, parseErr := strconv.Atoi(line)
		if parseErr != nil || strconv.Itoa(number) != line || number < 1 || number > len(current.LegalActions) {
			if _, err := io.WriteString(output, "Enter one of the displayed numbers.\n"); err != nil {
				return 1
			}
			continue
		}
		action := current.LegalActions[number-1]
		review := installation.Review(ctx, action)
		switch action {
		case proxyinstallation.ShowClientConfigurationAction:
			if review.Prepared == nil {
				latest = review.Result
				if writeRefusal(output, latest) != nil {
					return 1
				}
				current = installation.Review(ctx, proxyinstallation.StatusAction)
				continue
			}
			for _, line := range review.Plan {
				if _, err := fmt.Fprintln(output, line); err != nil {
					return 1
				}
			}
			confirmation, ok := readConfirmation(reader, output, "Show client configuration? [y/N]")
			if !ok {
				return 1
			}
			disclosed := false
			var disclosureErr error
			latest = installation.Execute(ctx, *review.Prepared, confirmation, func(progress proxyinstallation.Progress) {
				if disclosureErr != nil || len(progress.ClientConfiguration) == 0 {
					return
				}
				disclosed = true
				disclosureErr = writeClientConfiguration(output, progress.ClientConfiguration)
			})
			if disclosureErr != nil || latest.Code == proxyinstallation.ClientConfigurationDisclosed && !disclosed {
				return 1
			}
			if disclosed {
				if _, err := io.WriteString(output, "Press Enter to preserve this configuration in terminal scrollback and return to the menu.\n"); err != nil {
					return 1
				}
				if _, err := readLine(reader); err != nil && err != io.EOF {
					return 1
				}
			} else if writeRefusal(output, latest) != nil {
				return 1
			}
		case proxyinstallation.StartSetupAction, proxyinstallation.FinishCleanupAction, proxyinstallation.FinishSetupAction:
			if review.Prepared == nil {
				latest = review.Result
				if writeRefusal(output, latest) != nil {
					return 1
				}
				current = installation.Review(ctx, proxyinstallation.StatusAction)
				continue
			}
			for _, line := range review.Plan {
				if _, err := fmt.Fprintln(output, line); err != nil {
					return 1
				}
			}
			prompt := "Start proxy setup? [y/N]"
			if action == proxyinstallation.FinishCleanupAction {
				prompt = "Finish proxy cleanup? [y/N]"
			} else if action == proxyinstallation.FinishSetupAction {
				prompt = "Finish proxy setup? [y/N]"
			}
			confirmation, ok := readConfirmation(reader, output, prompt)
			if !ok {
				return 1
			}
			latest = installation.Execute(ctx, *review.Prepared, confirmation, func(progress proxyinstallation.Progress) {
				_, _ = fmt.Fprintln(output, "Progress:", progress.Phase)
			})
		case proxyinstallation.ViewDetailsAction:
			for _, detail := range review.Details {
				if _, err := fmt.Fprintln(output, detail); err != nil {
					return 1
				}
			}
			if _, err := io.WriteString(output, "Press Enter to return to the menu.\n"); err != nil {
				return 1
			}
			if _, err := readLine(reader); err != nil && err != io.EOF {
				return 1
			}
		default:
			latest = review.Result
			if writeRefusal(output, latest) != nil {
				return 1
			}
		}
		current = installation.Review(ctx, proxyinstallation.StatusAction)
	}
}

func writeClientConfiguration(output io.Writer, configuration []byte) error {
	if !json.Valid(configuration) {
		return errors.New("invalid client configuration")
	}
	var framed bytes.Buffer
	framed.WriteString("----- BEGIN SBXR CLIENT CONFIGURATION -----\n")
	framed.Write(configuration)
	if configuration[len(configuration)-1] != '\n' {
		framed.WriteByte('\n')
	}
	framed.WriteString("----- END SBXR CLIENT CONFIGURATION -----\n")
	_, err := io.Copy(output, &framed)
	return err
}

func writeFrame(output io.Writer, review proxyinstallation.Review, result proxyinstallation.Result) error {
	if _, err := fmt.Fprintf(output, "SBXR V3\nVersion: %s\nProxy status: %s\nResult: %s\nCode: %s\n\n", review.Version, review.Status, result.Message, result.Code); err != nil {
		return err
	}
	for index, action := range review.LegalActions {
		if _, err := fmt.Fprintf(output, "%d. %s\n", index+1, action); err != nil {
			return err
		}
	}
	_, err := io.WriteString(output, "0. Exit\n")
	return err
}

func writeRefusal(output io.Writer, result proxyinstallation.Result) error {
	if result.FailedCheck != "" {
		if _, err := fmt.Fprintf(output, "Failed safety check: %s\nCorrection: %s\n", result.FailedCheck, result.Correction); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(output, "Result: %s\nCode: %s\n", result.Message, result.Code)
	return err
}

func readConfirmation(reader *bufio.Reader, output io.Writer, prompt string) (proxyinstallation.Confirmation, bool) {
	for {
		if _, err := fmt.Fprintln(output, prompt); err != nil {
			return 0, false
		}
		line, err := readLine(reader)
		if errors.Is(err, errInputTooLong) {
			if _, err := io.WriteString(output, "Enter y or n.\n"); err != nil {
				return 0, false
			}
			continue
		}
		if err != nil && err != io.EOF {
			return 0, false
		}
		switch line {
		case "", "n":
			return proxyinstallation.Declined, true
		case "y":
			return proxyinstallation.Approved, true
		default:
			if _, err := io.WriteString(output, "Enter y or n.\n"); err != nil {
				return 0, false
			}
		}
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	var line []byte
	tooLong := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > 256 {
			tooLong = true
		}
		if !tooLong {
			line = append(line, fragment...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if tooLong {
			return "", errInputTooLong
		}
		value := strings.TrimSuffix(string(line), "\n")
		value = strings.TrimSuffix(value, "\r")
		return value, err
	}
}
