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
import "crypto/rand"
import "crypto/aes"
import "crypto/cipher"


/* 
 * Run file encryption
 */

func main() {
	// Check parameters
	if len(os.Args) < 2 {
		fmt.Printf("Invalid syntax\n\nencrypt <filepath>[ <AES key in hex>[ <IV in hex>]]\n")
		os.Exit(1)
	}

	// Get file path
	ipath := os.Args[1]

	// Generate random key
	var key []byte
	if len(os.Args) >= 3 {
		input_key, err := hex.DecodeString(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid key format.\n")
			os.Exit(2)
		}
		input_key_size := len(input_key)
		if input_key_size != 16 && input_key_size != 24 && input_key_size != 32 {
			fmt.Printf("Invalid key length.\n")
			os.Exit(2)
		}
		key = input_key
	} else {
		key = make([]byte, 32)
		rand.Read(key)
		fmt.Printf("Generated random key: %s\n", hex.EncodeToString(key))
	}

	// Generate random iv
	var iv []byte
	if len(os.Args) >= 4 {
		input_iv, err := hex.DecodeString(os.Args[3])
		if err != nil {
			fmt.Printf("Invalid IV format.\n")
			os.Exit(2)
		}
		input_iv_size := len(input_iv)
		if input_iv_size != aes.BlockSize {
			fmt.Printf("Invalid IV length.\n")
			os.Exit(2)
		}
		iv = input_iv
	} else {
		iv = make([]byte, aes.BlockSize)
		rand.Read(iv)
		fmt.Printf("Generated random IV: %s\n", hex.EncodeToString(iv))
	}

	// Open input file
	ifile, err := os.Open(ipath)
	if err != nil {
		fmt.Printf("Failed to open input file.\n")
		os.Exit(3)
	}
	defer ifile.Close()

	// Open output file
	opath := ipath + ".encrypted"
	ofile, err := os.OpenFile(opath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to open/create output file.\n")
		os.Exit(3)
	}
	defer ofile.Close()

	// Save IV to the file
	ofile.Write(iv)

	// Prepare encryption
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	stream := cipher.NewCTR(block, iv)
	ciphertext := make([]byte, 1024)

	// Prepare reader
	reader := bufio.NewReader(ifile)
	chunk := make([]byte, 1024)
	count := 0

	// Start reading and encrypting chunk by chunk
	for {
		if count, err = reader.Read(chunk); err != nil {
			break
		}
		stream.XORKeyStream(ciphertext, chunk[:count])
		ofile.Write(ciphertext[:count])
	}
	if err != io.EOF {
		fmt.Printf("Error while reading input file.\n")
		os.Exit(4)
	} else {
		err = nil
	}

	// Done!
	fmt.Printf("Done!\n")
	fmt.Printf("Encrypted file generated: %s\n", opath)
}
