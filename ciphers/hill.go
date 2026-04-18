package ciphers

import "github.com/ItakawaM/arcipher/ciphers/mathutils"

// inv2mod13 is the modular inverse of 2 modulo 13 (2 * 7 is congruent to 1 mod 13).
const inv2mod13 = 7

type HillCipher struct {
	Key        *mathutils.Matrix[int]
	InverseKey *mathutils.Matrix[int]
}

func crtCombine(numberA int, numberB int) int {
	/*
		Solve
		x is congruent to a mod 2
		x is congruent to b mod 13
	*/
	temp, _ := mathutils.Mod((numberB - numberA), 26)
	temp, _ = mathutils.Mod(temp*inv2mod13, 13)

	return (numberA + 2*temp)
}

func NewHillCipher(key *mathutils.Matrix[int]) (*HillCipher, error) {
	/*
		Z26 is isomorphic to Z2 x Z13, so we can just compute
		key inverse modulo 2 and key inverse modulo 13 and then
		use the chinese remainder theorem to find key inverse modulo 26

		x = a + 2 * ((b - a) * 2^(-1) mod 13)
	*/
	keyInverse2, err := mathutils.MatrixInverseModuloPrime(key, 2)
	if err != nil {
		return nil, err
	}

	keyInverse13, err := mathutils.MatrixInverseModuloPrime(key, 13)
	if err != nil {
		return nil, err
	}

	size := key.Rows()
	inverseKey, _ := mathutils.NewMatrixZero[int](size, size)

	for i := range size {
		for j := range size {
			inverseKey.Data[i][j] = crtCombine(keyInverse2.Data[i][j], keyInverse13.Data[i][j])
		}
	}

	return &HillCipher{
		Key:        key,
		InverseKey: inverseKey,
	}, nil
}

func (hc *HillCipher) IsInPlace() bool {
	return true
}

func (hc *HillCipher) EncryptBlock(dst []byte, src []byte) error {
	panic("NOT IMPLEMENTED")
}

func (hc *HillCipher) DecryptBlock(dst []byte, src []byte) error {
	panic("NOT IMPLEMENTED")
}
