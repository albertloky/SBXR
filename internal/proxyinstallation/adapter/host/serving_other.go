//go:build !linux

package host

func servingCapabilitiesRestricted() bool { return false }
