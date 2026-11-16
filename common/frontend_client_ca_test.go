package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestDecodeFrontendClientCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	encode := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct {
		name  string
		value string
		want  string
	}{
		{"one CA", encode(cert), cert},
		{"bundle", encode(cert + cert), cert + cert},
		{"raw PEM", cert, ""},
		{"empty", "", ""},
		{"invalid base64", "%?", ""},
		{"empty PEM", encode("    "), ""},
		{"malformed PEM", encode("-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n" + cert), ""},
		{"invalid DER", encode("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), ""},
		{"non-PEM tail", encode(cert + "extra"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeFrontendClientCA(tc.value)
			if (err == nil) != (tc.want != "") || string(got) != tc.want {
				t.Fatalf("decoded bundle length=%d err=%v; want length=%d", len(got), err, len(tc.want))
			}
		})
	}
}
