//go:build !linux

package main

import (
	"context"
	"errors"
	"os"
)

func openCurrentClientAccessExecutable() (*os.File, error) {
	return nil, errors.New("Client Access changes are supported only on Linux")
}
func verifyClientAccessProcess(*os.File, *os.File) error {
	return errors.New("Client Access changes are supported only on Linux")
}
func startClientAccessProcess(context.Context, *os.File) (*os.File, func() error, error) {
	return nil, nil, errors.New("Client Access changes are supported only on Linux")
}
