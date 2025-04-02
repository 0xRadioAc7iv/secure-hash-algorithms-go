package main

import (
	"encoding/binary"
	"fmt"
)

// Initial Hash Values (from square roots of primes)
var h0 uint32 = 0x67452301
var h1 uint32 = 0xEFCDAB89
var h2 uint32 = 0x98BADCFE
var h3 uint32 = 0x10325476
var h4 uint32 = 0xC3D2E1F0

// SHA-0 Constants (for different rounds)
var K = [4]uint32{0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6}

// SHA-0 Padding Function
func padMessage(message []byte) []byte {
	origLen := len(message) * 8     // Length in bits
	message = append(message, 0x80) // Append '1' bit

	// Append '0' bits until length ≡ 448 mod 512
	for (len(message)*8)%512 != 448 {
		message = append(message, 0x00)
	}

	// Append the original message length as a 64-bit big-endian integer
	lenBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lenBytes, uint64(origLen))
	message = append(message, lenBytes...)

	return message
}

// SHA-0 Main Hashing Function
func sha0(message []byte) [20]byte {
	// Preprocessing: Padding the message
	message = padMessage(message)

	// Process the message in 512-bit (64-byte) blocks
	for i := 0; i < len(message); i += 64 {
		// Break into 16 32-bit words
		var W [80]uint32
		for j := range 16 {
			W[j] = binary.BigEndian.Uint32(message[i+j*4 : i+j*4+4])
		}

		// Extend to 80 words (WITHOUT rotation, unlike SHA-1)
		for j := 16; j < 80; j++ {
			W[j] = W[j-3] ^ W[j-8] ^ W[j-14] ^ W[j-16]
		}

		// Initialize hash values for this chunk
		a, b, c, d, e := h0, h1, h2, h3, h4

		// Main Loop (80 rounds)
		for j := range 80 {
			var f uint32
			var k uint32

			switch {
			case j < 20:
				f = (b & c) | (^b & d) // IF function
				k = K[0]
			case j < 40:
				f = b ^ c ^ d // XOR function
				k = K[1]
			case j < 60:
				f = (b & c) | (b & d) | (c & d) // Majority function
				k = K[2]
			default:
				f = b ^ c ^ d
				k = K[3]
			}

			temp := leftRotate(a, 5) + f + e + k + W[j]
			e = d
			d = c
			c = leftRotate(b, 30)
			b = a
			a = temp
		}

		// Add this chunk's hash to result
		h0 += a
		h1 += b
		h2 += c
		h3 += d
		h4 += e
	}

	// Final hash value (160 bits)
	var digest [20]byte
	binary.BigEndian.PutUint32(digest[0:], h0)
	binary.BigEndian.PutUint32(digest[4:], h1)
	binary.BigEndian.PutUint32(digest[8:], h2)
	binary.BigEndian.PutUint32(digest[12:], h3)
	binary.BigEndian.PutUint32(digest[16:], h4)

	return digest
}

// Left Rotate Function
func leftRotate(value uint32, bits uint) uint32 {
	return (value << bits) | (value >> (32 - bits))
}

// Convert Hash to Hex String
func hashToHex(hash [20]byte) string {
	return fmt.Sprintf("%x", hash)
}

func main() {
	var input string

	fmt.Print("Enter something: ")
	_, err := fmt.Scan(&input)

	if err != nil {
		fmt.Println(err)
		return
	}

	message := []byte(input)
	hash := sha0(message)

	fmt.Println("SHA-0 Hash:", hashToHex(hash))
}
