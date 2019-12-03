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
 * Example AES encryption in CBC (Cipher Block Chaining) mode
 *
 * Encryption
 *         +-----+   +-----+       +-----+   Where, 
 *         | B_1 |   | B_2 |       | B_n |     B_x   is the x^th block of the plain-text
 *         +-----+   +-----+       +-----+     IV    is a random initialization vector
 *  +----+    |         |             |        AES_K is the AES cipher block encryption with key K
 *  | IV +----+    +----+    +--------+        C_x   is the x^th block of the cipher-text
 *  +----+    |    |    |    |        |   
 *         +-----+ | +-----+ |     +-----+
 *         |AES_K| | |AES_K| | ... |AES_K|
 *         +-----+ | +-----+ |     +-----+
 *            |    |    |    |        |   
 *            +----+    +----+        |   
 *            |         |             |   
 *         +-----+   +-----+       +-----+
 *         | C_1 |   | C_2 |       | C_n |
 *         +-----+   +-----+       +-----+
 * 
 * Decryption
 *         +-----+   +-----+       +-----+   Where, 
 *         | C_1 |   | C_2 |       | C_n |     C_x   is the x^th block of the cipher-text
 *         +-----+   +-----+       +-----+     AES_K is the AES cipher block decryption with key K
 *            |         |             |        IV    is the initialization vector used in encryption
 *            +----+    +----+        |        B_x   is the x^th block of the plain-text
 *            |    |    |    |        |   
 *         +-----+ | +-----+ |     +-----+
 *         |AES_K| | |AES_K| | ... |AES_K|
 *         +-----+ | +-----+ |     +-----+
 *  +----+    |    |    |    |        |   
 *  | IV +----+    +----+    +--------+   
 *  +----+    |         |             |   
 *         +-----+   +-----+       +-----+
 *         | B_1 |   | B_2 |       | B_n |
 *         +-----+   +-----+       +-----+
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

// PKCS#7 padding
// We basically append n bytes with the value n at the end of the message
func add_pkcs7_padding(input []byte, blocksize int) []byte {
	data := input
	// Calculate pad number
	n := blocksize - (len(data) % blocksize)
	// Fill rest with n
	for i := 0; i < n; i++ {
		data = append(data, byte(n))
	}
	return data
}

func remove_pkcs7_padding(data []byte) []byte {
	// Start checking from the back to frond
	i := len(data) - 1
	// Get last byte
	n := data[i];
	// Check last n bytes
	l := i - int(n)
	for i > l {
		// If not n
		if data[i] != n {
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
 * AES in CBC Mode
 * Cipher Block Chaining
 */

func encrypt_AES_CBC(plaintext []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	block_mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	block_mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext
}

func decrypt_AES_CBC(ciphertext []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	block_mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	block_mode.CryptBlocks(plaintext, ciphertext)

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
	fmt.Printf("Using AES-%d in CBC mode and PKCS#7 padding\n\n", 8*AES_SIZE)

	// Generate random key
	key := make([]byte, AES_SIZE)
	rand.Read(key)
	fmt.Printf(" ~ Key (hex)\n%s\n", hex.EncodeToString(key))

	// Generate random iv
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	fmt.Printf(" ~ IV (hex)\n%s\n", hex.EncodeToString(iv))

	// The message we want to encrypt
	message_string := "This is a message to be encrypted with AES in CBC mode."
	message := []byte(message_string)
	message_padded := add_pkcs7_padding(message, aes.BlockSize);

	fmt.Printf(" ~ Message (ascii)\n%s\n", string(message))
	fmt.Printf(" ~ Message (hex)\n%s\n", hex.EncodeToString(message))
	fmt.Printf(" ~ Message padded (hex)\n%s\n", hex.EncodeToString(message_padded))

	// Encrypted message
	encrypted_message := encrypt_AES_CBC(message_padded, key, iv)
	fmt.Printf(" ~ Encrypted Message (hex)\n%s\n", hex.EncodeToString(encrypted_message))

	// Decrypted message
	decrypted_message_padded := decrypt_AES_CBC(encrypted_message, key, iv)
	decrypted_message := remove_pkcs7_padding(decrypted_message_padded);
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
