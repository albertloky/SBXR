package systemchanges

const recoveryServiceUnit = `[Unit]
Description=SBXR restart recovery
After=network-online.target
Before=xray.service sing-box.service cloudflared.service sbxr-subscription.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sbxr private recover

[Install]
WantedBy=multi-user.target
`

func SystemdUnits() map[string]string {
	return map[string]string{"sbxr-recovery.service": recoveryServiceUnit}
}
