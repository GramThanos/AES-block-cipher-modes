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
 * Example AES encryption in CTR (Counter) mode
 *
 * Encryption
 *        +-------+    +-------+     +-------+    Where, 
 *        |IV + 00|    |IV + 01|     |IV +  n|          IV    is a random initialization vector
 *        +-------+    +-------+     +-------+          B_x   is the x^th block of the plain-text
 *            |            |             |              AES_K is the AES cipher block encryption with key K
 *         +-----+      +-----+       +-----+           C_x   is the x^th block of the cipher-text
 *         |AES_K|      |AES_K|       |AES_K|     
 *         +-----+      +-----+       +-----+     
 *            | +-----+    | +-----+     | +-----+
 *            | | B_1 |    | | B_2 | ... | | B_n |
 *            | +-----+    | +-----+     | +-----+
 *            |    |       |    |        |    |   
 *            +----+       +----+        +----+   
 *                 |            |             |   
 *              +-----+      +-----+       +-----+
 *              | C_1 |      | C_2 |       | C_n |
 *              +-----+      +-----+       +-----+
 * 
 * Decryption
 *        +-------+    +-------+     +-------+    Where, 
 *        |IV + 00|    |IV + 01|     |IV +  n|          IV    is the initialization vector used in encryption
 *        +-------+    +-------+     +-------+          AES_K is the AES cipher block decryption with key K
 *            |            |             |              C_x   is the x^th block of the cipher-text
 *         +-----+      +-----+       +-----+           B_x   is the x^th block of the plain-text
 *         |AES_K|      |AES_K|       |AES_K|     
 *         +-----+      +-----+       +-----+     
 *            | +-----+    | +-----+     | +-----+
 *            | | C_1 |    | | C_2 | ... | | C_n |
 *            | +-----+    | +-----+     | +-----+
 *            |    |       |    |        |    |   
 *            +----+       +----+        +----+   
 *                 |            |             |   
 *              +-----+      +-----+       +-----+
 *              | B_1 |      | B_2 |       | B_n |
 *              +-----+      +-----+       +-----+
 */

package main

import "fmt"
import "encoding/hex"
import "crypto/rand"
import "crypto/aes"
import "crypto/cipher"



/* 
 * AES in CTR Mode
 * Output FeedBack
 */

func encrypt_AES_CTR(plaintext []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)

	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	return ciphertext
}

func decrypt_AES_CTR(ciphertext []byte, key []byte, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, iv)

	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

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
	fmt.Printf("Using AES-%d in CTR\n\n", 8*AES_SIZE)

	// Generate random key
	key := make([]byte, AES_SIZE)
	rand.Read(key)
	fmt.Printf(" ~ Key (hex)\n%s\n", hex.EncodeToString(key))

	// Generate random iv
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	fmt.Printf(" ~ IV (hex)\n%s\n", hex.EncodeToString(iv))

	// The message we want to encrypt
	message_string := "This is a message to be encrypted with AES in CTR mode."
	message := []byte(message_string)
	
	fmt.Printf(" ~ Message (ascii)\n%s\n", string(message))
	fmt.Printf(" ~ Message (hex)\n%s\n", hex.EncodeToString(message))

	// Encrypted message
	encrypted_message := encrypt_AES_CTR(message, key, iv)
	fmt.Printf(" ~ Encrypted Message (hex)\n%s\n", hex.EncodeToString(encrypted_message))

	// Decrypted message
	decrypted_message := decrypt_AES_CTR(encrypted_message, key, iv)
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
