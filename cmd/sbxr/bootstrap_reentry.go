package main

import (
	"encoding/json"
	"errors"
	"os"
	"syscall"

	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const installRecoveryReceipt = "/var/lib/sbxr-recovery.json"

type recoveryReceipt struct {
	Schema             uint64 `json:"schema"`
	ChangeSet          string `json:"change_set"`
	Repository         string `json:"repository"`
	Tag                string `json:"tag"`
	Commit             string `json:"commit"`
	ReleaseIndexSHA256 string `json:"release_index_sha256"`
	PayloadSHA256      string `json:"payload_sha256"`
}

func writeInstallRecoveryReceipt(changeSet string, identity softwarelifecycle.ReleaseIdentity, payloadSHA256 string) error {
	if !safeRecoveryChangeSet(changeSet) {
		return errors.New("install recovery receipt refused")
	}
	body, err := json.Marshal(recoveryReceipt{Schema: 1, ChangeSet: changeSet, Repository: identity.Repository, Tag: identity.Tag, Commit: identity.Commit, ReleaseIndexSHA256: identity.IndexSHA256, PayloadSHA256: payloadSHA256})
	if err != nil {
		return err
	}
	body = append(body, '\n')
	file, err := os.OpenFile(installRecoveryReceipt, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		_ = os.Remove(installRecoveryReceipt)
		return err
	}
	written, writeErr := file.Write(body)
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(body) {
		_ = os.Remove(installRecoveryReceipt)
		return errors.New("install recovery receipt unavailable")
	}
	return syncInstallRecoveryReceiptDirectory()
}

func removeInstallRecoveryReceipt() error {
	if err := os.Remove(installRecoveryReceipt); err != nil {
		return err
	}
	return syncInstallRecoveryReceiptDirectory()
}

func syncInstallRecoveryReceiptDirectory() error {
	directory, err := os.Open("/var/lib")
	if err != nil {
		return err
	}
	syncErr, closeErr := directory.Sync(), directory.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func clientAccessRecoveryMarker() bool {
	report, err := readOwnVersion()
	return err == nil && validClientAccessRecoveryMarker(installRecoveryReceipt, report, 0)
}

func validClientAccessRecoveryMarker(name string, report versionReport, uid uint32) bool {
	info, err := os.Lstat(name)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 || stat.Uid != uid || stat.Nlink != 1 || info.Size() > 1024 {
		return false
	}
	body, err := os.ReadFile(name)
	var receipt recoveryReceipt
	return err == nil && json.Unmarshal(body, &receipt) == nil && receipt.Schema == 1 && safeRecoveryChangeSet(receipt.ChangeSet) && receipt.Repository == report.Build.Repository && receipt.Tag == report.Build.Tag && receipt.Commit == report.Build.Commit && receipt.PayloadSHA256 == report.Build.PayloadSHA256 && lowercaseHex(receipt.ReleaseIndexSHA256, 64) && lowercaseHex(receipt.PayloadSHA256, 64)
}

func lowercaseHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func safeRecoveryChangeSet(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}
