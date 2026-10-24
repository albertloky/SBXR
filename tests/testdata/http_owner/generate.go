package main

import ("encoding/json";"strings";"crypto/sha256";"fmt";"os")

type ServingAuthority struct {
	HTTP                  bool      `json:"http,omitempty"`
	LinkID                string    `json:"link_id"`
	CredentialSHA256      string    `json:"credential_sha256"`
	CertificateGeneration int       `json:"certificate_generation"`
	CertificateSHA256     [4]string `json:"certificate_sha256"`
}

func subscriptionFirewallUnit(ipv4 string) string {
	rule80 := `-d ` + ipv4 + `/32 -p tcp --dport 80 -m comment --comment sbxr-subscription -j ACCEPT`
	rule8443 := `-d ` + ipv4 + `/32 -p tcp --dport 8443 -m comment --comment sbxr-subscription -j ACCEPT`
	command := `/usr/sbin/iptables -w`
	return `[Unit]
Description=SBXR Subscription Firewall
Before=sbxr-subscription.service snap.certbot.renew.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -ec '` + command + ` -C INPUT ` + rule80 + ` || ` + command + ` -I INPUT 1 ` + rule80 + `'
ExecStart=/bin/sh -ec '` + command + ` -C INPUT ` + rule8443 + ` || ` + command + ` -I INPUT 1 ` + rule8443 + `'
ExecStop=/bin/sh -ec 'while ` + command + ` -C INPUT ` + rule8443 + `; do ` + command + ` -D INPUT ` + rule8443 + `; done'
ExecStop=/bin/sh -ec 'while ` + command + ` -C INPUT ` + rule80 + `; do ` + command + ` -D INPUT ` + rule80 + `; done'

[Install]
WantedBy=multi-user.target
`
}

func httpSubscriptionFirewallUnit(ipv4 string) string {
	unit := subscriptionFirewallUnit(ipv4)
	var lines []string
	for _, line := range strings.Split(unit, "\n") {
		if !strings.Contains(line, "--dport 80 ") {
			lines = append(lines, strings.ReplaceAll(line, " snap.certbot.renew.service", ""))
		}
	}
	return strings.Join(lines, "\n")
}

func servingStateBytes(serving ServingAuthority) []byte {
	body, _ := json.Marshal(struct {
		Schema  int              `json:"schema"`
		Serving ServingAuthority `json:"serving"`
	}{Schema: 1, Serving: serving})
	return append(body, '\n')
}

func main(){
 if len(os.Args)!=2 {panic("fixture directory required")}
 if err:=os.WriteFile(os.Args[1]+"/firewall.service",[]byte(httpSubscriptionFirewallUnit("8.8.8.8")),0600);err!=nil{panic(err)}
 authority:=ServingAuthority{HTTP:true,LinkID:strings.Repeat("1",32),CredentialSHA256:fmt.Sprintf("%x",sha256.Sum256([]byte(strings.Repeat("A",43))))}
 if err:=os.WriteFile(os.Args[1]+"/serving-state.json",servingStateBytes(authority),0600);err!=nil{panic(err)}
}
