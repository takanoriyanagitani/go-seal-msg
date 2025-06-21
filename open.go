package sealmsg

import (
	"crypto/cipher"
	"errors"
	"fmt"
)

var (
	ErrTooShortMsg error = errors.New("too short combined message")
)

type SealedMessage struct {
	Nonce      [12]byte
	CipherText []byte
	Tag        [16]byte
}

type CombinedData []byte

func (c CombinedData) ToSealed() (SealedMessage, error) {
	var empty SealedMessage

	var minSize int = 12 + 16
	var input []byte = c
	var isz int = len(input)

	if isz < minSize {
		return empty, fmt.Errorf("%w: %v", ErrTooShortMsg, len(input))
	}

	copy(empty.Nonce[:], input)
	copy(empty.Tag[:], input[isz-16:])

	empty.CipherText = input[12 : isz-16]

	return empty, nil
}

func (o OneTimeKey) Open(nonce []byte, ciphertext []byte) (plaintext []byte, e error) {
	blk, err := SymmetricKey(o).NewBlock()
	if nil != err {
		return nil, err
	}

	aead, err := cipher.NewGCM(blk)
	if nil != err {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}

func (o OneTimeKey) OpenMessage(msg SealedMessage) (plaintext []byte, e error) {
	var cipherTxt []byte = msg.CipherText
	var tag []byte = msg.Tag[:]

	var cipherTag []byte = append(cipherTxt, tag...)
	return o.Open(msg.Nonce[:], cipherTag)
}
