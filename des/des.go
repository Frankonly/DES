package des

import (
	"encoding/binary"
)

// All data stored in one uint64/uint32 is serialized in big endian
// with non-data zeros at head.
// Example 4|28 means (four bits non-data zeros)|(28 bits data).
type Cipher struct {
	subKeys [16]uint64
}

func NewCipher(key []byte) *Cipher {
	if len(key) < 8 {
		key = append(key, make([]byte, 8-len(key))...)
	}

	c := new(Cipher)
	c.generateSubKeys(key)
	return c
}

func (c *Cipher) Encrypt(src []byte) (dst []byte) {
	if len(src) != 8 {
		panic("wrong block size")
	}
	dst = c.cryptBlock(src, false)
	return
}

func (c *Cipher) Decrypt(src []byte) (dst []byte) {
	if len(src) != 8 {
		panic("wrong block size")
	}
	dst = c.cryptBlock(src, true)
	return
}

func (c *Cipher) cryptBlock(src []byte, decrypt bool) (dst []byte) {
	dst = make([]byte, 8)

	b := binary.BigEndian.Uint64(src)         // 0|64
	b = permute(b, 64, initialPermutation[:]) // 0|64
	left, right := uint32(b>>32), uint32(b)   // 0|32

	if decrypt {
		for i := 0; i < 16; i++ {
			left, right = feistel(left, right, c.subKeys[15-i]) // 0|32
		}
	} else {
		for i := 0; i < 16; i++ {
			left, right = feistel(left, right, c.subKeys[i]) // 0|32
		}
	}

	preOutput := (uint64(right) << 32) | uint64(left) // 0|64
	binary.BigEndian.PutUint64(dst, permute(preOutput, 64, finalPermutation[:]))
	return
}

func (c *Cipher) generateSubKeys(keyBytes []byte) {
	key := binary.BigEndian.Uint64(keyBytes)   // 0|64
	key = permute(key, 64, permutedChoice1[:]) // 8|56
	cSet := displace(uint32(key >> 28))        // 4|28
	dSet := displace(uint32(key<<4) >> 4)      // 4|28
	for i := 0; i < 16; i++ {
		connect := uint64(cSet[i])<<28 | uint64(dSet[i])        // 8|56
		c.subKeys[i] = permute(connect, 56, permutedChoice2[:]) // 16|48
	}
}

func feistel(left, right uint32, subKey uint64) (uint32, uint32) {
	//fmt.Printf("\n%032b---%032b", left, right)
	e := permute(uint64(right), 32, expansion[:]) // 16|48
	s := substitute(e ^ subKey)                   // 0|32
	p := uint32(permute(uint64(s), 32, pBox[:]))  // 0|32
	return right, left ^ p                        // 0|32
}

func substitute(src uint64) (s uint32) {
	for i, box := range sBoxes {
		bits := uint8(src >> (48 - (i+1)*6))
		row := (bits>>5)&1<<1 | bits&1
		column := bits << 3 >> 4
		s |= uint32(box[row][column]) << (4 * (7 - i))
	}
	return
}

func permute(src uint64, length uint8, permutation []uint8) (block uint64) {
	for position, n := range permutation {
		bit := (src >> (length - n) & 1)
		block |= bit << uint((len(permutation)-1)-position)
	}
	return
}

func displace(in uint32) (out []uint32) {
	out = make([]uint32, 16)
	last := in
	for i := 0; i < 16; i++ {
		left := (last << (4 + displacements[i])) >> 4
		right := (last << 4) >> (32 - displacements[i])
		out[i] = (left | right)
		last = out[i]
	}
	return
}
