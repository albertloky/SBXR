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
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

var errInputTooLong = errors.New("input line too long")

// Run owns one numbered-menu session.
func Run(ctx context.Context, arguments []string, input io.Reader, output, errorOutput io.Writer, installation proxyinstallation.Interface, lifecycle softwarelifecycle.Interface) int {
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
		if writeFrame(output, current, latest, lifecycle, ctx) != nil {
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
		if parseErr != nil || strconv.Itoa(number) != line || number < 1 || number > len(current.LegalActions)+lifecycleChoiceCount(lifecycle) {
			if _, err := io.WriteString(output, "Enter one of the displayed numbers.\n"); err != nil {
				return 1
			}
			continue
		}
		if number > len(current.LegalActions) {
			if !runLifecycle(ctx, reader, output, lifecycle, number-len(current.LegalActions)) {
				return 1
			}
			current = installation.Review(ctx, proxyinstallation.StatusAction)
			latest = current.Result
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
		case proxyinstallation.StartSetupAction, proxyinstallation.FinishCleanupAction, proxyinstallation.FinishSetupAction, proxyinstallation.EnableSubscriptionAction, proxyinstallation.RotateSubscriptionLinkAction, proxyinstallation.RepairSubscriptionAction, proxyinstallation.FinishSubscriptionChangeAction, proxyinstallation.RotateClientIdentityAction, proxyinstallation.FinishClientIdentityAction:
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
			} else if action == proxyinstallation.EnableSubscriptionAction {
				prompt = "Enable subscription? [y/N]"
			} else if action == proxyinstallation.RotateSubscriptionLinkAction {
				prompt = "Rotate subscription link? [y/N]"
			} else if action == proxyinstallation.RepairSubscriptionAction {
				prompt = "Repair subscription? [y/N]"
			} else if action == proxyinstallation.FinishSubscriptionChangeAction {
				prompt = "Finish subscription change? [y/N]"
			} else if action == proxyinstallation.RotateClientIdentityAction {
				prompt = "Rotate Client Identity? [y/N]"
			} else if action == proxyinstallation.FinishClientIdentityAction {
				prompt = "Finish Client Identity rotation? [y/N]"
			}
			confirmation, ok := readConfirmation(reader, output, prompt)
			if !ok {
				return 1
			}
			var subscriptionLink []byte
			var progressErr error
			latest = installation.Execute(ctx, *review.Prepared, confirmation, func(progress proxyinstallation.Progress) {
				if progressErr != nil {
					return
				}
				if progress.Phase != "" {
					_, progressErr = fmt.Fprintln(output, "Progress:", progress.Phase)
				}
				if len(progress.SubscriptionLink) > 0 {
					subscriptionLink = bytes.Clone(progress.SubscriptionLink)
				}
			})
			if action == proxyinstallation.EnableSubscriptionAction && latest.Code == proxyinstallation.SubscriptionEnabled || action == proxyinstallation.RotateSubscriptionLinkAction && latest.Code == proxyinstallation.SubscriptionLinkRotated {
				if progressErr != nil || len(subscriptionLink) == 0 || writeSubscriptionLink(output, subscriptionLink) != nil {
					_ = writeRefusal(errorOutput, proxyinstallation.Result{Code: proxyinstallation.SubscriptionLinkDisplayIncomplete, Message: "The subscription change completed, but link display did not complete. Use View details."})
					return 1
				}
				if action == proxyinstallation.RotateSubscriptionLinkAction {
					if _, err := io.WriteString(output, "Replace the old link in Karing. The old link no longer works. Your proxy Client Identity has not changed.\n"); err != nil {
						_ = writeRefusal(errorOutput, proxyinstallation.Result{Code: proxyinstallation.SubscriptionLinkDisplayIncomplete, Message: "The subscription change completed, but link display did not complete. Use View details."})
						return 1
					}
				}
				if _, err := io.WriteString(output, "Press Enter to preserve this link in terminal scrollback and return to the menu.\n"); err != nil {
					_ = writeRefusal(errorOutput, proxyinstallation.Result{Code: proxyinstallation.SubscriptionLinkDisplayIncomplete, Message: "The subscription change completed, but link display did not complete. Use View details."})
					return 1
				}
				if _, err := readLine(reader); err != nil && err != io.EOF {
					return 1
				}
			} else if progressErr != nil {
				if clientIdentityCompleted(latest.Code) {
					_ = writeClientIdentityDisplayIncomplete(errorOutput)
				}
				return 1
			} else if action == proxyinstallation.EnableSubscriptionAction || action == proxyinstallation.RotateSubscriptionLinkAction || action == proxyinstallation.RotateClientIdentityAction || action == proxyinstallation.FinishClientIdentityAction {
				if writeRefusal(output, latest) != nil {
					if clientIdentityCompleted(latest.Code) {
						_ = writeClientIdentityDisplayIncomplete(errorOutput)
					}
					return 1
				}
			}
		case proxyinstallation.CompleteRemovalAction:
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
			confirmation, ok := readCompleteRemovalConfirmation(reader, output)
			if !ok {
				return 1
			}
			latest = installation.Execute(ctx, *review.Prepared, confirmation, func(progress proxyinstallation.Progress) {
				_, _ = fmt.Fprintln(output, "Progress:", progress.Phase)
			})
			if writeRefusal(output, latest) != nil {
				return 1
			}
			if latest.Code == proxyinstallation.CompleteRemovalCompleted {
				return 0
			}
		case proxyinstallation.FinishRemovalAction:
			if review.Prepared == nil {
				latest = review.Result
				if writeRefusal(output, latest) != nil {
					return 1
				}
				current = installation.Review(ctx, proxyinstallation.StatusAction)
				continue
			}
			latest = installation.Execute(ctx, *review.Prepared, proxyinstallation.Approved, func(progress proxyinstallation.Progress) {
				_, _ = fmt.Fprintln(output, "Progress:", progress.Phase)
			})
			if writeRefusal(output, latest) != nil {
				return 1
			}
			if latest.Code == proxyinstallation.CompleteRemovalCompleted {
				return 0
			}
		case proxyinstallation.ViewDetailsAction:
			for _, detail := range review.Details {
				if _, err := fmt.Fprintln(output, detail); err != nil {
					return 1
				}
			}
			if len(review.SubscriptionLink) > 0 {
				if writeSubscriptionLink(output, review.SubscriptionLink) != nil {
					_, _ = io.WriteString(errorOutput, "Subscription link output failed.\n")
					return 1
				}
				latest = proxyinstallation.Result{Status: review.Status, SubscriptionStatus: review.SubscriptionStatus, Code: proxyinstallation.SubscriptionLinkDisclosed, Message: "The subscription link was displayed. Keep it private."}
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

func clientIdentityCompleted(code proxyinstallation.ResultCode) bool {
	return code == proxyinstallation.ClientIdentityRotated || code == proxyinstallation.ClientIdentityRotationFinished
}

func writeClientIdentityDisplayIncomplete(output io.Writer) error {
	return writeRefusal(output, proxyinstallation.Result{Code: proxyinstallation.ClientIdentityRotationDisplayIncomplete, Message: "Client Identity rotation completed, but result display did not complete. Use View details."})
}

func writeSubscriptionLink(output io.Writer, link []byte) error {
	if len(link) == 0 || bytes.ContainsAny(link, "\r\n") {
		return errors.New("invalid subscription link")
	}
	if _, err := io.WriteString(output, "This link is a reusable credential. Anyone with it can obtain your proxy connection details. Keep it private. It will remain in terminal scrollback.\n"); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "%s\n", link)
	return err
}

func readCompleteRemovalConfirmation(reader *bufio.Reader, output io.Writer) (proxyinstallation.Confirmation, bool) {
	if _, err := io.WriteString(output, "Type REMOVE SBXR to confirm Complete removal. Any other input cancels.\n"); err != nil {
		return 0, false
	}
	line, err := readLine(reader)
	if err != nil && err != io.EOF && !errors.Is(err, errInputTooLong) {
		return 0, false
	}
	if line == "REMOVE SBXR" {
		return proxyinstallation.Approved, true
	}
	return proxyinstallation.Declined, true
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

func writeFrame(output io.Writer, review proxyinstallation.Review, result proxyinstallation.Result, lifecycle softwarelifecycle.Interface, ctx context.Context) error {
	if _, err := fmt.Fprintf(output, "SBXR V3\nVersion: %s\nProxy status: %s\nSubscription status: %s\nProxy traffic availability: %s\nSubscription serving availability: %s\nResult: %s\nCode: %s\n\n", review.Version, review.Status, review.SubscriptionStatus, review.ProxyTraffic, review.SubscriptionServing, result.Message, result.Code); err != nil {
		return err
	}
	for index, action := range review.LegalActions {
		if _, err := fmt.Fprintf(output, "%d. %s\n", index+1, action); err != nil {
			return err
		}
	}
	if lifecycle != nil {
		if err := writeLifecycleResult(output, lifecycle.Status(ctx)); err != nil {
			return err
		}
		for index, label := range []string{"Check", "Update", "Recover"} {
			if _, err := fmt.Fprintf(output, "%d. %s\n", len(review.LegalActions)+index+1, label); err != nil {
				return err
			}
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
