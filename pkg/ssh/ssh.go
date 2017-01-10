package ssh

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ssh"

	libmachine "github.com/docker/machine/libmachine/ssh"
)

// Client is an SSH client wrapper for libmachine
type Client interface {
	libmachine.Client
}

// NewClient returns an SSH client
func NewClient(details Details) (client Client, err error) {
	user := details.GetSSHUsername()
	addr := details.GetSSHAddress()
	port := details.GetSSHPort()
	auth := &libmachine.Auth{Keys: []string{details.GetSSHKeyPath()}}

	client, err = libmachine.NewClient(user, addr, port, auth)
	return client, err
}

// Details is an interface for the details to allow to SSH into nodes
type Details interface {
	GetSSHAddress() string
	GetSSHPort() int
	GetSSHKeyPath() string
	GetSSHUsername() string
}

// ValidUnecryptedPrivateKey parses SSH private key
func ValidUnecryptedPrivateKey(file string) error {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	isEncrypted, err := isEncrypted(buffer)
	if err != nil {
		return fmt.Errorf("Parse SSH key error")
	}

	if isEncrypted {
		return fmt.Errorf("Encrypted SSH key is not permitted")
	}

	_, err = ssh.ParsePrivateKey(buffer)
	if err != nil {
		return fmt.Errorf("Parse SSH key error: %v", err)
	}

	return nil
}

func isEncrypted(buffer []byte) (bool, error) {
	// There is no error, just a nil block
	block, _ := pem.Decode(buffer)
	// File cannot be decoded, maybe it's some unecpected format
	if block == nil {
		return false, fmt.Errorf("Parse SSH key error")
	}

	return x509.IsEncryptedPEMBlock(block), nil
}
