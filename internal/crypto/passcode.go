package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// Passcode-protected encryption for escrowed leaf private keys. Independent of
// the keystore master key: a caller-supplied passcode derives a fresh key via
// scrypt, so the escrowed key cannot be decrypted without that passcode even
// by an operator holding the master key. This layers an application-level
// guard on top of keystore at-rest encryption.
//
// Blob layout: [ salt(16) | nonce(12) | AES-256-GCM ciphertext ]
const (
	passcodeSaltSize  = 16
	passcodeNonceSize = 12
	passcodeKeyLen    = 32
)

// EncryptWithPasscode derives a key from passcode (scrypt) and seals plaintext
// with AES-256-GCM. Returns the self-describing blob.
func EncryptWithPasscode(plaintext, passcode []byte) ([]byte, error) {
	if len(passcode) == 0 {
		return nil, errors.New("passcode: passcode must not be empty")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("passcode: refusing to encrypt empty plaintext")
	}

	salt := make([]byte, passcodeSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("passcode: salt: %w", err)
	}
	key, err := scrypt.Key(passcode, salt, 1<<15, 8, 1, passcodeKeyLen)
	if err != nil {
		return nil, fmt.Errorf("passcode: derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("passcode: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("passcode: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("passcode: nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)

	blob := make([]byte, 0, passcodeSaltSize+len(sealed))
	blob = append(blob, salt...)
	blob = append(blob, sealed...)
	return blob, nil
}

// DecryptWithPasscode reverses EncryptWithPasscode, returning the plaintext
// only if passcode is correct.
func DecryptWithPasscode(blob, passcode []byte) ([]byte, error) {
	min := passcodeSaltSize + passcodeNonceSize + 16
	if len(blob) < min {
		return nil, errors.New("passcode: blob too short")
	}
	salt := blob[:passcodeSaltSize]
	sealed := blob[passcodeSaltSize:]

	key, err := scrypt.Key(passcode, salt, 1<<15, 8, 1, passcodeKeyLen)
	if err != nil {
		return nil, fmt.Errorf("passcode: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("passcode: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("passcode: gcm: %w", err)
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("passcode: blob malformed")
	}
	nonce := sealed[:gcm.NonceSize()]
	ciphertext := sealed[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("passcode: decryption failed — incorrect passcode")
	}
	return plain, nil
}
