package ssh

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	libmachinessh "github.com/docker/machine/libmachine/ssh"
	"golang.org/x/crypto/ssh"
)

// Client produces libmachine ssh
type Client interface {
	NewClient() (*libmachinessh.Client, error)
}

// Details is an interface to allow to SSH into nodes
type Details interface {
	GetSSHAddress()
	GetSSHPort()
	GetSSHKeyPath()
	GetSSHUsername()
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
