// internal/crypto/keystore.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// Keystore encrypts and decrypts private keys at rest using AES-256-GCM.
type Keystore struct {
	masterKey []byte
}

// NewKeystore creates a Keystore from a 32-byte master key.
func NewKeystore(masterKey []byte) (*Keystore, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("keystore: master key must be exactly 32 bytes, got %d", len(masterKey))
	}
	key := make([]byte, 32)
	copy(key, masterKey)
	return &Keystore{masterKey: key}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (ks *Keystore) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("keystore: refusing to encrypt empty plaintext")
	}

	block, err := aes.NewCipher(ks.masterKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("keystore: generate nonce: %w", err)
	}
	blob := gcm.Seal(nonce, nonce, plaintext, nil)
	return blob, nil
}

// Decrypt decrypts a blob produced by Encrypt.
func (ks *Keystore) Decrypt(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("keystore: refusing to decrypt empty blob")
	}

	block, err := aes.NewCipher(ks.masterKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("keystore: create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(blob) < nonceSize+1+16 {
		return nil, fmt.Errorf("keystore: blob too short (%d bytes), minimum is %d", len(blob), nonceSize+1+16)
	}

	nonce := blob[:nonceSize]
	ciphertext := blob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("keystore: decryption failed — wrong master key or corrupted blob")
	}

	return plaintext, nil
}

// EncryptPEM validates that src is a valid PEM block before encrypting it.
func (ks *Keystore) EncryptPEM(src []byte) ([]byte, error) {
	block, _ := pem.Decode(src)
	if block == nil {
		return nil, errors.New("keystore: EncryptPEM: input is not valid PEM")
	}
	return ks.Encrypt(src)
}

// DecryptPEM decrypts a blob and validates that the result is valid PEM.
func (ks *Keystore) DecryptPEM(blob []byte) ([]byte, error) {
	plaintext, err := ks.Decrypt(blob)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(plaintext)
	if block == nil {
		return nil, errors.New("keystore: DecryptPEM: decrypted data is not valid PEM — possible corruption or wrong master key")
	}
	return plaintext, nil
}

// Zero wipes the master key from memory. Call this on shutdown.
func (ks *Keystore) Zero() {
	for i := range ks.masterKey {
		ks.masterKey[i] = 0
	}
}

// GenerateMasterKey generates a cryptographically random 32-byte master key
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("keystore: generate master key: %w", err)
	}
	return key, nil
}
