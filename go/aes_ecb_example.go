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
 * Example AES encryption in ECB (Electronic Code Book) mode
 *
 * Encryption
 *  +-----+  +-----+     +-----+   Where, 
 *  | B_1 |  | B_2 |     | B_n |     B_x   is the x^th block of the plain-text
 *  +-----+  +-----+     +-----+     AES_K is the AES cipher block encryption with key K
 *     |        |           |        C_x   is the x^th block of the cipher-text
 *  +-----+  +-----+     +-----+
 *  |AES_K|  |AES_K| ... |AES_K|
 *  +-----+  +-----+     +-----+
 *     |        |           |   
 *  +-----+  +-----+     +-----+
 *  | C_1 |  | C_2 |     | C_n |
 *  +-----+  +-----+     +-----+
 * 
 * Decryption
 *  +-----+  +-----+     +-----+   Where, 
 *  | C_1 |  | C_2 |     | C_n |     C_x   is the x^th block of the cipher-text
 *  +-----+  +-----+     +-----+     AES_K is the AES cipher block decryption with key K
 *     |        |           |        B_x   is the x^th block of the plain-text
 *  +-----+  +-----+     +-----+
 *  |AES_K|  |AES_K| ... |AES_K|
 *  +-----+  +-----+     +-----+
 *     |        |           |   
 *  +-----+  +-----+     +-----+
 *  | B_1 |  | B_2 |     | B_n |
 *  +-----+  +-----+     +-----+
 */

package main

import "fmt"
import "encoding/hex"
import "crypto/rand"
import "crypto/aes"



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



/* 
 * AES in ECB Mode
 * Electronic Code Book
 */

func encrypt_AES_ECB(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	size := len(plaintext)
	if size % aes.BlockSize != 0 {
		panic("Plaintext should be a multiple of AES block.")
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < size; i += aes.BlockSize {
		block.Encrypt(ciphertext[i : i + aes.BlockSize], plaintext[i : i + aes.BlockSize])
	}

	return ciphertext
}

func decrypt_AES_ECB(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	size := len(ciphertext)
	if size % aes.BlockSize != 0 {
		panic("Ciphertext should be a multiple of AES block.")
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < size; i += aes.BlockSize {
		block.Decrypt(plaintext[i : i + aes.BlockSize], ciphertext[i : i + aes.BlockSize])
	}
	
	return plaintext
}



/* 
 * Run test
 */

func main() {
	// Size of AES's key in bytes
	// AES-128 : 16 bytes
	// AES-192 : 24 bytes
	// AES-256 : 32 bytes
	const AES_SIZE = 32;

	// Report AES key size and mode
	fmt.Printf("Using AES-%d in ECB mode and ISO/IEC 9797-1 method 2 padding\n\n", 8*AES_SIZE)

	// Generate random key
	key := make([]byte, AES_SIZE)
	rand.Read(key)
	fmt.Printf(" ~ Key (hex)\n%s\n", hex.EncodeToString(key))

	// The message we want to encrypt
	message_string := "This is a message to be encrypted with AES in ECB mode."
	message := []byte(message_string)
	message_padded := add_iso_padding(message, aes.BlockSize);

	fmt.Printf(" ~ Message (ascii)\n%s\n", string(message))
	fmt.Printf(" ~ Message (hex)\n%s\n", hex.EncodeToString(message))
	fmt.Printf(" ~ Message padded (hex)\n%s\n", hex.EncodeToString(message_padded))

	// Encrypted message
	encrypted_message := encrypt_AES_ECB(message_padded, key)
	fmt.Printf(" ~ Encrypted Message (hex)\n%s\n", hex.EncodeToString(encrypted_message))

	// Decrypted message
	decrypted_message_padded := decrypt_AES_ECB(encrypted_message, key)
	decrypted_message := remove_iso_padding(decrypted_message_padded);
	fmt.Printf(" ~ Decrypted Message padded (hex)\n%s\n", hex.EncodeToString(decrypted_message_padded))
	fmt.Printf(" ~ Decrypted Message (hex)\n%s\n", hex.EncodeToString(decrypted_message))
	fmt.Printf(" ~ Decrypted Message (ascii)\n%s\n", string(decrypted_message))

	// Test result
	fmt.Printf("Test: ")
	if string(message) == string(decrypted_message) {
		fmt.Printf("PASSED")
	} else {
		fmt.Printf("FAILED")
	}
	fmt.Printf("\n\n")
}
