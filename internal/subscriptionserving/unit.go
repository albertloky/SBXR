package subscriptionserving

const serviceUnit = `[Unit]
Description=SBXR subscription service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sbxr-subscription
Group=sbxr-subscription
ExecStart=/usr/local/bin/sbxr __subscription-serve
StandardOutput=null
StandardError=null
Restart=on-failure
RestartSec=5s
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
PrivateDevices=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
LimitCORE=0
TemporaryFileSystem=/:ro
BindReadOnlyPaths=/usr/local/bin/sbxr
BindReadOnlyPaths=/var/lib/sbxr/subscriptions/current
BindReadOnlyPaths=/var/lib/sbxr/certificates/ip/current
BindReadOnlyPaths=/etc/ssl/certs/ca-certificates.crt

[Install]
WantedBy=multi-user.target
`

func ServiceUnit() string { return serviceUnit }
