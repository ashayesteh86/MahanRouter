// Package pki makes the self-signed certificates the router hands out.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"regexp"
	"time"
)

var certNameRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// SelfSignedCert returns a PEM certificate and RSA key for name (a host
// name or IP address). It is its own CA, so Windows can import it under
// Trusted Root Certification Authorities.
func SelfSignedCert(name string, valid time.Duration) (string, string, error) {
	if !certNameRe.MatchString(name) {
		return "", "", errors.New("name must be the host name or IP address clients dial")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Mahan Router"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(valid),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	c := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	k := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(c), string(k), nil
}

// ServerCertWithCA returns a new certificate authority, and a server
// certificate and RSA key for name signed by it. The authority's key is
// thrown away: clients install the authority once, and a new server
// certificate means a new authority. iOS and macOS refuse a server
// certificate that is its own authority, so IKEv2 needs the pair.
func ServerCertWithCA(name string, valid time.Duration) (caPEM, certPEM, keyPEM string, err error) {
	if !certNameRe.MatchString(name) {
		return "", "", "", errors.New("name must be the host name or IP address clients dial")
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	serial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		return n
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Mahan Router VPN CA (" + name + ")", Organization: []string{"Mahan Router"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(valid),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	leaf := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Mahan Router"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(valid),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
		// Windows matches the name it dialled against DNS names only.
		leaf.DNSNames = []string{name}
	} else {
		leaf.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	enc := func(t string, b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b})) }
	return enc("CERTIFICATE", caDER), enc("CERTIFICATE", der), enc("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)), nil
}
