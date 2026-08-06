package certificatelifecycle

import (
	"embed"
	"io/fs"
)

//go:embed systemd/*
var systemdUnits embed.FS

func SystemdUnits() (map[string]string, error) {
	entries, err := fs.ReadDir(systemdUnits, "systemd")
	if err != nil {
		return nil, err
	}
	units := make(map[string]string, len(entries))
	for _, entry := range entries {
		content, err := systemdUnits.ReadFile("systemd/" + entry.Name())
		if err != nil {
			return nil, err
		}
		units[entry.Name()] = string(content)
	}
	return units, nil
}
