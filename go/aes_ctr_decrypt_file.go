/*
 * University of Piraeus
 * MSc Digital Systems Security
 * 
 * 2nd assignment for the course "Network Security"
 * Tutor : Christos Xenakis
 *
 * Use the Advanced Encryption Standard (AES) block cipher
 * in it's most popular modes.
 *
 * MIT License
 *
 * Copyright (c) 2019 Grammatopoulos Athanasios-Vasileios
 */

package main

import "os"
import "io"
import "fmt"
import "bufio"
import "encoding/hex"
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
 * Run file encryption
 */

func main() {
	// Check parameters
	if len(os.Args) < 3 {
		fmt.Printf("Invalid syntax\n\ndecrypt <filepath> <AES key in hex>\n")
		os.Exit(1)
	}

	// Get file path
	ipath := os.Args[1]

	// Generate random key
	var key []byte
	key, err := hex.DecodeString(os.Args[2])
	if err != nil {
		fmt.Printf("Invalid key format.\n")
		os.Exit(2)
	}
	key_size := len(key)
	if key_size != 16 && key_size != 24 && key_size != 32 {
		fmt.Printf("Invalid key length.\n")
		os.Exit(2)
	}

	// Open input file
	ifile, err := os.Open(ipath)
	if err != nil {
		fmt.Printf("Failed to open input file.\n")
		os.Exit(3)
	}
	defer ifile.Close()

	// Open output file
	opath := ipath + ".decrypted"
	ofile, err := os.OpenFile(opath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to open/create output file.\n")
		os.Exit(3)
	}
	defer ofile.Close()

	// Prepare reader
	reader := bufio.NewReader(ifile)
	chunk := make([]byte, 1024)
	count := 0

	// Read random iv from input
	iv := make([]byte, aes.BlockSize)
	if count, err = reader.Read(iv); err != nil {
		fmt.Printf("Failed to recover IV.\n")
		os.Exit(4)
	}
	fmt.Printf("Recovered IV: %s\n", hex.EncodeToString(iv))

	// Prepare decryption
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, iv)
	plaintext := make([]byte, 1024)

	// Start reading and decrypting chunk by chunk
	for {
		if count, err = reader.Read(chunk); err != nil {
			break
		}
		stream.XORKeyStream(plaintext, chunk[:count])
		ofile.Write(plaintext[:count])
	}
	if err != io.EOF {
		fmt.Printf("Error while reading input file.\n")
	} else {
		err = nil
	}

	// Done!
	fmt.Printf("Done!\n")
}
