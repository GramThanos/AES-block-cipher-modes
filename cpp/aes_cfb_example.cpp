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
 * Example AES encryption in CFB (Cipher FeedBack) mode
 * 
 * Encryption
 *              +-----+       +-----+           +-----+   Where, 
 *              | B_1 |       | B_2 |           | B_n |     B_x   is the x^th block of the plain-text
 *              +-----+       +-----+           +-----+     IV    is a random initialization vector
 *  +----+         |             |                 |        AES_K is the AES cipher block encryption with key K
 *  | IV +----+    |   +----+    |   +--------+    |        C_x   is the x^th block of the cipher-text
 *  +----+    |    |   |    |    |   |        |    |   
 *         +-----+ |   | +-----+ |   |     +-----+ |   
 *         |AES_K| |   | |AES_K| |   | ... |AES_K| |   
 *         +-----+ |   | +-----+ |   |     +-----+ |   
 *            |    |   |    |    |   |        |    |   
 *            +-->(+)  |    +-->(+)  |        +-->(+)  
 *                 |   |         |   |             |   
 *                 |---+         |---+             |   
 *                 |             |                 |   
 *              +-----+       +-----+           +-----+
 *              | C_1 |       | C_2 |           | C_n |
 *              +-----+       +-----+           +-----+
 * 
 * Decryption
 *              +-----+       +-----+           +-----+   Where, 
 *              | C_1 |       | C_2 |           | C_n |     C_x   is the x^th block of the cipher-text
 *              +-----+       +-----+           +-----+     AES_K is the AES cipher block decryption with key K
 *  +----+         |             |                 |        IV    is the initialization vector used in encryption
 *  | IV +----+    +--------+    +------------+    |        B_x   is the x^th block of the plain-text
 *  +----+    |    |        |    |            |    |   
 *         +-----+ |     +-----+ |         +-----+ |   
 *         |AES_K| |     |AES_K| |    ...  |AES_K| |   
 *         +-----+ |     +-----+ |         +-----+ |   
 *            |    |        |    |            |    |   
 *            +-->(+)       +-->(+)           +-->(+)  
 *                 |             |                 |   
 *              +-----+       +-----+           +-----+
 *              | B_1 |       | B_2 |           | B_n |
 *              +-----+       +-----+           +-----+
 */

#include <stdio.h>
#include <stdlib.h>
#include <iomanip>
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
#include <string>
using std::string;
#include <cstdlib>
using std::exit;

#include "aes.h"
#include "osrng.h"
#include "modes.h"
#include "filters.h"
#include "cryptlib.h"



/* 
 * AES in CFB Mode
 * Cipher Feedback
 */

std::vector<unsigned char> encrypt_AES_CFB(std::vector<unsigned char> plaintext, std::vector<unsigned char> key_vector, std::vector<unsigned char> iv_vector) {
	string plain(plaintext.begin(), plaintext.end());
	string cipher;
	unsigned char *key = &key_vector.front();
	unsigned char *iv = &iv_vector.front();

	try {
		CryptoPP::CFB_Mode< CryptoPP::AES >::Encryption e;
		e.SetKeyWithIV(key, key_vector.size(), iv);
		
		CryptoPP::StringSource(plain, true, 
			new CryptoPP::StreamTransformationFilter(e,
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::BlockPaddingScheme::NO_PADDING
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(EXIT_FAILURE);
	}

	std::vector<unsigned char> cipher_vector(cipher.begin(), cipher.end());
	return cipher_vector;
}

std::vector<unsigned char> decrypt_AES_CFB(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key_vector, std::vector<unsigned char> iv_vector) {
	string cipher(ciphertext.begin(), ciphertext.end());
	string plain;
	unsigned char *key = &key_vector.front();
	unsigned char *iv = &iv_vector.front();

	try {
		CryptoPP::CFB_Mode< CryptoPP::AES >::Decryption d;
		d.SetKeyWithIV(key, key_vector.size(), iv);

		CryptoPP::StringSource s(cipher, true, 
			new CryptoPP::StreamTransformationFilter(d,
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::BlockPaddingScheme::NO_PADDING
			)
		);
	}
	catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(EXIT_FAILURE);
	}

	std::vector<unsigned char> plain_vector(plain.begin(), plain.end());
	return plain_vector;
}



/* 
 * Run test
 */

int main(int argc, char* argv[]) {
	// Size of AES's key in bytes
	// AES-128 : 16 bytes
	// AES-192 : 24 bytes
	// AES-256 : 32 bytes
	unsigned char AES_SIZE = 32;

	// Report AES key size and mode
	cout << "Using AES-" << (8*AES_SIZE) << " in CFB mode" << endl << endl;

	// Generate random key
	unsigned char key_bytes[AES_SIZE];
	CryptoPP::AutoSeededRandomPool prng;
	prng.GenerateBlock(key_bytes, sizeof(key_bytes));
	std::vector<unsigned char> key;
	for (int i = 0; i < sizeof(key_bytes); ++i)
		key.push_back(key_bytes[i]);

	cout << " ~ Key (hex)" << endl;
	for (auto val : key) printf("%.2x", val);
	cout << endl;

	// Generate random iv
	unsigned char iv_bytes[16];
	prng.GenerateBlock(iv_bytes, sizeof(iv_bytes));
	std::vector<unsigned char> iv;
	for (int i = 0; i < sizeof(iv_bytes); ++i)
		iv.push_back(iv_bytes[i]);

	cout << " ~ IV (hex)" << endl;
	for (auto val : iv) printf("%.2x", val);
	cout << endl;

	// The message we want to encrypt
	string message_string = "This is a message to be encrypted with AES in CFB mode.";
	std::vector<unsigned char> message(message_string.begin(), message_string.end());

	cout << " ~ Message (ascii)" << endl;
	for (auto val : message) printf("%c", val);
	cout << endl;
	cout << " ~ Message (hex)" << endl;
	for (auto val : message) printf("%.2x", val);
	cout << endl;

	// Encrypted message
	std::vector<unsigned char> encrypted_message = encrypt_AES_CFB(message, key, iv);
	cout << " ~ Encrypted Message (hex)" << endl;
	for (auto val : encrypted_message) printf("%.2x", val);
	cout << endl;

	// Decrypted message
	std::vector<unsigned char> decrypted_message = decrypt_AES_CFB(encrypted_message, key, iv);
	cout << " ~ Decrypted Message (ascii)" << endl;
	for (auto val : decrypted_message) printf("%c", val);
	cout << endl;
	cout << " ~ Decrypted Message (hex)" << endl;
	for (auto val : decrypted_message) printf("%.2x", val);
	cout << endl;
	string decrypted_message_string(decrypted_message.begin(), decrypted_message.end());

	// Test result
	cout << "Test: ";
	if (message_string.compare(decrypted_message_string) == 0) {
		cout << "PASSED";
	} else {
		cout << "FAILED";
	}
	cout << endl << endl;
}
