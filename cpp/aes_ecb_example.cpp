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
 * Help functions
 */

// ISO/IEC 9797-1 padding method 2
// So ... 1000..000 padding
/*
std::vector<unsigned char> add_iso_padding(std::vector<unsigned char> input, int blocksize) {
	std::vector<unsigned char> data(input);
	data.push_back(0x80);
	for (int i = blocksize - (data.size() % blocksize); i > 0; i--) {
		data.push_back(0x0);
	}
	return data;
}

std::vector<unsigned char> remove_iso_padding(std::vector<unsigned char> input) {
	std::vector<unsigned char> data(input);
	// Start checking from the back to frond
	int i = data.size() - 1;
	while (i >= 0) {
		// If 0b10000000 stop
		if (data.at(i) == 0x80) {
			data.pop_back();
			i--;
			break;
		}
		// If not zeros invalid
		if (data.at(i) != 0x0) {
			printf("Invalid padding.");
			exit(EXIT_FAILURE);
		}
		data.pop_back();
		i--;
	}
	if (i < 0) {
		printf("Failed to remove padding.");
		exit(EXIT_FAILURE);
	}
	
	return data;
}
*/



/* 
 * AES in ECB Mode
 * Electronic Code Book
 */

std::vector<unsigned char> encrypt_AES_ECB(std::vector<unsigned char> plaintext, std::vector<unsigned char> key_vector) {
	string plain(plaintext.begin(), plaintext.end());
	string cipher;
	unsigned char *key = &key_vector.front();

	try {
		CryptoPP::ECB_Mode< CryptoPP::AES >::Encryption e;
		e.SetKey(key, key_vector.size());
		
		CryptoPP::StringSource(plain, true, 
			new CryptoPP::StreamTransformationFilter(e,
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::BlockPaddingScheme::ONE_AND_ZEROS_PADDING
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

std::vector<unsigned char> decrypt_AES_ECB(std::vector<unsigned char> ciphertext, std::vector<unsigned char> key_vector) {
	string cipher(ciphertext.begin(), ciphertext.end());
	string plain;
	unsigned char *key = &key_vector.front();

	try {
		CryptoPP::ECB_Mode< CryptoPP::AES >::Decryption d;
		d.SetKey(key, key_vector.size());

		CryptoPP::StringSource s(cipher, true, 
			new CryptoPP::StreamTransformationFilter(d,
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::BlockPaddingScheme::ONE_AND_ZEROS_PADDING
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
	//cout << "Using AES-" << (8*AES_SIZE) << " in ECB mode and ISO/IEC 9797-1 method 2 padding" << endl << endl;
	cout << "Using AES-" << (8*AES_SIZE) << " in ECB mode" << endl << endl;

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

	// The message we want to encrypt
	string message_string = "This is a message to be encrypted with AES in ECB mode.";
	std::vector<unsigned char> message(message_string.begin(), message_string.end());

	cout << " ~ Message (ascii)" << endl;
	for (auto val : message) printf("%c", val);
	cout << endl;
	cout << " ~ Message (hex)" << endl;
	for (auto val : message) printf("%.2x", val);
	cout << endl;

	// Encrypted message
	std::vector<unsigned char> encrypted_message = encrypt_AES_ECB(message, key);
	cout << " ~ Encrypted Message (hex)" << endl;
	for (auto val : encrypted_message) printf("%.2x", val);
	cout << endl;

	// Decrypted message
	std::vector<unsigned char> decrypted_message = decrypt_AES_ECB(encrypted_message, key);
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
