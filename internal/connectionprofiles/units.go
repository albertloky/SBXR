package connectionprofiles

const xrayServiceUnit = `[Unit]
Description=SBXR Xray service
After=network-online.target sbxr-recovery.service

[Service]
Type=simple
User=xray
Group=xray
ExecStart=/usr/bin/xray run -config /etc/sbxr/xray/config.json
Restart=on-failure
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
`

const singBoxServiceUnit = `[Unit]
Description=SBXR sing-box service
After=network-online.target sbxr-recovery.service

[Service]
Type=simple
User=sing-box
Group=sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sbxr/sing-box/config.json
Restart=on-failure
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectHome=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
`

func SystemdUnits() map[string]string {
	return map[string]string{"sing-box.service": singBoxServiceUnit, "xray.service": xrayServiceUnit}
}
