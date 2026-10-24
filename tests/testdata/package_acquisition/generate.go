//go:build ignore

// Fixed PUBLIC test keys and long-lived loopback certificates; never deploy.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	root := ed25519.NewKeyFromSeed(append([]byte{4}, make([]byte, 31)...))
	seed := make([]byte, 32)
	seed[0] = 5
	leaf := ed25519.NewKeyFromSeed(seed)
	start := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SBXR PUBLIC synthetic test CA"}, NotBefore: start, NotAfter: end, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, root.Public(), root)
	if e != nil {
		panic(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "SBXR loopback fixture"}, DNSNames: []string{"sing-box.app", "deb.sagernet.org", "gemfury.s3-accelerate.dualstack.amazonaws.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: start, NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, ca, leaf.Public(), root)
	if e != nil {
		panic(e)
	}
	key, e := x509.MarshalPKCS8PrivateKey(leaf)
	if e != nil {
		panic(e)
	}
	write := func(name, kind string, b []byte) {
		if e := os.WriteFile(name, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b}), 0600); e != nil {
			panic(e)
		}
	}
	write("ca.pem", "CERTIFICATE", caDER)
	write("server.pem", "CERTIFICATE", der)
	write("server-key.pem", "PRIVATE KEY", key)
}
