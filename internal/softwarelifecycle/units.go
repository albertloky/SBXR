package softwarelifecycle

const updateCheckServiceUnit = `[Unit]
Description=SBXR verified update check
After=network-online.target sbxr-recovery.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sbxr private update-check
`

const updateCheckTimerUnit = `[Unit]
Description=Run SBXR verified update check

[Timer]
OnCalendar=daily
Persistent=true
Unit=sbxr-update-check.service

[Install]
WantedBy=timers.target
`

func SystemdUnits() map[string]string {
	return map[string]string{"sbxr-update-check.service": updateCheckServiceUnit, "sbxr-update-check.timer": updateCheckTimerUnit}
}
