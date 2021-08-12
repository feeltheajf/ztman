package pki

import (
	"encoding/pem"
	"errors"
)

func encode(t PEMType, b []byte) string {
	block := &pem.Block{
		Type:  string(t),
		Bytes: b,
	}
	return string(pem.EncodeToMemory(block))
}

func decode(raw string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	return block, nil
}
