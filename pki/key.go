package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

	"golang.org/x/crypto/ssh"

	"github.com/feeltheajf/ztman/config"
)

// WritePublicKey saves public key to file
func WritePublicKey(filename string, key crypto.PublicKey) error {
	b, err := MarshalPublicKey(key)
	if err != nil {
		return err
	}
	return config.Write(filename, b)
}

// MarshalPublicKey returns PEM encoding of key
func MarshalPublicKey(key crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  pemTypePublicKey,
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// WritePublicKeySSH saves public key to file in OpenSSH format
func WritePublicKeySSH(filename string, key crypto.PublicKey) error {
	b, err := MarshalPublicKeySSH(key)
	if err != nil {
		return err
	}
	return config.Write(filename, b)
}

// MarshalPublicKeySSH returns OpenSSH encoding of key
func MarshalPublicKeySSH(key crypto.PublicKey) ([]byte, error) {
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, err
	}
	return []byte(base64.StdEncoding.EncodeToString(pub.Marshal())), nil
}
