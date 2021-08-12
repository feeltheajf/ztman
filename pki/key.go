package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"

	"golang.org/x/crypto/ssh"

	"github.com/feeltheajf/ztman/fs"
)

// WritePublicKey saves public key to file
func WritePublicKey(filename string, key crypto.PublicKey) error {
	raw, err := MarshalPublicKey(key)
	if err != nil {
		return err
	}
	return fs.Write(filename, raw)
}

// MarshalPublicKey returns PEM encoding of key
func MarshalPublicKey(key crypto.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return encode(PEMTypePublicKey, b), nil
}

// WritePublicKeySSH saves public key to file in OpenSSH format
func WritePublicKeySSH(filename string, key crypto.PublicKey) error {
	raw, err := MarshalPublicKeySSH(key)
	if err != nil {
		return err
	}
	return fs.Write(filename, raw)
}

// MarshalPublicKeySSH returns OpenSSH encoding of key
func MarshalPublicKeySSH(key crypto.PublicKey) (string, error) {
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub.Marshal()), nil
}
