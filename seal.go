package sealmsg

import (
	"crypto/aes"
	"crypto/cipher"
)

type SymmetricKey [32]byte

func (k SymmetricKey) NewBlock() (cipher.Block, error) {
	return aes.NewCipher(k[:])
}

type OneTimeKey SymmetricKey

// Creates [cipher.AEAD] using random nonce.
//
// The use of a constant(e.g., 0) nonce is acceptable only if the key is
// REALLY used once(accidental reuse of the key and the nonce must be avoided).
func (o OneTimeKey) NewGCMWithRandomNonce() (cipher.AEAD, error) {
	blk, e := SymmetricKey(o).NewBlock()
	if nil != e {
		return nil, e
	}

	return cipher.NewGCMWithRandomNonce(blk)
}

// Seals the plaintext using random nonce.
func (o OneTimeKey) Seal(plaintext []byte) (ciphertext []byte, e error) {
	aead, err := o.NewGCMWithRandomNonce()
	if nil != err {
		return nil, err
	}

	return aead.Seal(nil, nil, plaintext, nil), nil
}
