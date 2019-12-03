/*
 * University of Piraeus
 * MSc Digital Systems Security
 * 
 * 2nd assignment for the course "Network Security"
 * Tutor : Christos Xenakis
 *
 * Use the Advanced Encryption Standard (AES) block cipher
 * in its most popular modes.
 *
 * MIT License
 *
 * Copyright (c) 2019 Grammatopoulos Athanasios-Vasileios
 *
 * 
 * Example AES CMAC (Cipher-based Message Authentication Code)
 */

package main

import "fmt"
import "encoding/hex"
import "crypto/rand"
import "crypto/aes"
import "crypto/cipher"



/* 
 * Help functions
 */

// ISO/IEC 9797-1 padding method 2
// So ... 1000..000 padding

func add_iso_padding(input []byte, blocksize int) []byte {
	data := input
	// Insert 0b10000000
	data = append(data, 0x80)
	// Fill rest with zeros
	for i := blocksize - (len(data) % blocksize); i > 0; i-- {
		data = append(data, 0x0)
	}
	return data
}

func remove_iso_padding(data []byte) []byte {
	// Start checking from the back to frond
	i := len(data) - 1
	for i >= 0 {
		// If 0b10000000 stop
		if data[i] == 0x80 {
			i--
			break
		}
		// If not zeros invalid
		if data[i] != 0x0 {
			panic("Invalid padding.")
		}
		i--
	}
	if i < 0 {
		panic("Failed to remove padding.")
	}
	
	return data[:i + 1]
}


// Bit shift on a byte array
func array_shift_bit_left(in []byte) []byte {
	out := make([]byte, len(in))
	var b byte = 0x0
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = (in[i] << 1) | b // Shift and add previous shifted bit at lsb
		b = in[i] >> 7 // Get msb to be shifted on the next byte group
	}
	return out
}

// Bitwise xor on a byte array
func array_xor(a []byte, b []byte) []byte {
	c := make([]byte, len(a))
	for i := len(a) - 1; i >= 0; i-- {
		c[i] = (a[i] ^ b[i])
	}
	return c
}



/* 
 * AES-CMAC
 * Cipher based Message Authentication Code using AES-128 as the block cipher
 * This code is based on https://tools.ietf.org/html/rfc4493
 */

func generate_AES_CMAC(message []byte, key []byte) []byte {
	// Generate keys
	k1, k2 := generate_AES_CMAC_subkey(key)

	// Prepare AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Pad message if not multiple of AES block size
	message_aligned := make([]byte, len(message))
	copy(message_aligned, message)
	l := len(message_aligned)
	if l % aes.BlockSize != 0 || l == 0 {
		// Pad
		message_aligned = add_iso_padding(message_aligned, aes.BlockSize)
		l = len(message_aligned)
		// XOR last block with K2
		for i , j := 0, l - aes.BlockSize; i < aes.BlockSize; i , j = i+1, j+1 {
			message_aligned[j] = message_aligned[j] ^ k2[i]
		}
	} else {
		// XOR last block with K1
		for i , j := 0, l - aes.BlockSize; i < aes.BlockSize; i , j = i+1, j+1 {
			message_aligned[j] = message_aligned[j] ^ k1[i]
		}
	}

	ciphertext := make([]byte, len(message_aligned))

	block_mode := cipher.NewCBCEncrypter(block, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	block_mode.CryptBlocks(ciphertext, message_aligned)

	// Only the last block is the MAC
	cmac := ciphertext[len(ciphertext) - aes.BlockSize:]

	return cmac
}

func generate_AES_CMAC_subkey(key []byte) ([]byte, []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	
	Zero := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	Rb   := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87}

	L := make([]byte, len(key))
	block.Encrypt(L, Zero)
	key1 := array_shift_bit_left(L)
	if (L[0] & 0x80) != 0x0 {
		key1 = array_xor(key1, Rb)	
	}
	key2 := array_shift_bit_left(key1)
	if (key1[0] & 0x80) != 0x0 {
		key2 = array_xor(key2, Rb)
	}

	return key1, key2
}

func validate_AES_CMAC(message []byte, key []byte, cmac []byte) bool {
	generate_cmac := generate_AES_CMAC(message, key)

	count := 0
	for i := len(cmac) - 1; i >= 0; i-- {
		if generate_cmac[i] == cmac[i] {
			count ++
		}
	}

	return count == len(cmac)
}



/* 
 * Run test
 */

func main() {
	fmt.Printf("Generating AES-CMAC\n\n")

	// Generate random key (AES-CMAC works with 128)
	key := make([]byte, 16)
	rand.Read(key)
	//key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	fmt.Printf(" ~ Key (hex)\n%s\n", hex.EncodeToString(key))

	// The message we want to authenticate
	message_string := "This is a message from which we want to generate a CMAC with AES."
	message := []byte(message_string)
	//message := []byte{}
	
	fmt.Printf(" ~ Message (ascii)\n%s\n", string(message))
	fmt.Printf(" ~ Message (hex)\n%s\n", hex.EncodeToString(message))

	// CMAC tag
	cmac_tag := generate_AES_CMAC(message, key)
	fmt.Printf(" ~ Message's CMAC tag (hex)\n%s\n", hex.EncodeToString(cmac_tag))

	// Test result
	fmt.Printf("Test: ")
	if validate_AES_CMAC(message, key, cmac_tag) {
		fmt.Printf("PASSED")
	} else {
		fmt.Printf("FAILED")
	}
	fmt.Printf("\n\n")
}
