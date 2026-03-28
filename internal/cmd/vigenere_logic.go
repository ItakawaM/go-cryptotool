package cmd

import "github.com/ItakawaM/go-cryptotool/ciphers"

type vigenereFactory struct {
	key []byte
}

func (vF *vigenereFactory) name() string {
	return "vigenere"
}

func (vF *vigenereFactory) parseKey(keyStr string) error {
	normalizedKey, err := ciphers.NormalizeVigenereKey([]byte(keyStr))
	if err != nil {
		return err
	}
	vF.key = normalizedKey

	return nil
}

func (vF *vigenereFactory) newCipher(_ int) (ciphers.BlockCipher, error) {
	return ciphers.NewVigenereCipherNormalized(vF.key), nil
}
