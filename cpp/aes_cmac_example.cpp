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
 * 
 * CMAC Generation
 *                                  +-----------------+     Where, 
 *                                  | |B_n| % bs != 0 |           B_x   is the x^th block of the plain-text
 *                                  +-----------------+           |B_n| is the length of the last block
 *                                         |                      bs    is the block size, 16 bytes in our case
 *                     +-----+ +--------+  |  +----+ +----+       AES_K is the AES cipher block encryption with key K
 *                     | B_n | |B_n|10^i|  |  | K1 | | K2 |       TAG   is the CMAC output
 *                     +-----+ +--------+  |  +----+ +----+
 *                         |     |         |     |     |   
 * +-----+     +-----+    +-------+        |    +-------+  
 * | B_1 |     | B_2 |     \ SEL /<--------+---->\ SEL /   
 * +-----+     +-----+      +---+                 +---+    
 *    |           |           |                     |      
 *    |     +--->(+)    +--->(+)<-------------------+      
 *    |     |     |     |     |                            
 * +-----+  |  +-----+  |  +-----+                         
 * |AES_K|  |  |AES_K|  |  |AES_K|                         
 * +-----+  |  +-----+  |  +-----+                         
 *    |     |     |     |     |                            
 *    +-----+     +-----+     |                            
 *                            |                            
 *                         +-----+                         
 *                         | TAG |                         
 *                         +-----+                         
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
#include "cmac.h"
#include "osrng.h"
#include "modes.h"
#include "filters.h"
#include "cryptlib.h"



/* 
 * AES-CMAC
 * Cipher based Message Authentication Code using AES-128 as the block cipher
 */

std::vector<unsigned char> generate_AES_CMAC(std::vector<unsigned char> message, std::vector<unsigned char> key_vector) {
	string plain(message.begin(), message.end());
	string mac;
	unsigned char *key = &key_vector.front();

	try {
		CryptoPP::CMAC< CryptoPP::AES > cmac(key, key_vector.size());
		
		CryptoPP::StringSource(plain, true, 
			new CryptoPP::HashFilter(cmac,
				new CryptoPP::StringSink(mac)
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(EXIT_FAILURE);
	}

	std::vector<unsigned char> mac_vector(mac.begin(), mac.end());
	return mac_vector;
}

bool validate_AES_CMAC(std::vector<unsigned char> message, std::vector<unsigned char> key_vector, std::vector<unsigned char> mac_vector) {
	string plain(message.begin(), message.end());
	string mac(mac_vector.begin(), mac_vector.end());
	unsigned char *key = &key_vector.front();

	try {
		CryptoPP::CMAC< CryptoPP::AES > cmac(key, key_vector.size());
		
		CryptoPP::StringSource(plain + mac, true, 
			new CryptoPP::HashVerificationFilter(cmac, NULL,
				CryptoPP::HashVerificationFilter::THROW_EXCEPTION | CryptoPP::HashVerificationFilter::HASH_AT_END
			)
		);

		return true;
	}
	catch (const CryptoPP::Exception& e) {
		return false;
	}
	return false;
}



/* 
 * Run test
 */

int main(int argc, char* argv[]) {
	cout << "Generating AES-CMAC" << endl << endl;

	// Generate random key (AES-CMAC works with 128)
	unsigned char key_bytes[16];
	CryptoPP::AutoSeededRandomPool prng;
	prng.GenerateBlock(key_bytes, sizeof(key_bytes));
	std::vector<unsigned char> key;
	for (int i = 0; i < sizeof(key_bytes); ++i)
		key.push_back(key_bytes[i]);

	cout << " ~ Key (hex)" << endl;
	for (auto val : key) printf("%.2x", val);
	cout << endl;

	// The message we want to encrypt
	string message_string = "This is a message from which we want to generate a CMAC with AES.";
	std::vector<unsigned char> message(message_string.begin(), message_string.end());

	cout << " ~ Message (ascii)" << endl;
	for (auto val : message) printf("%c", val);
	cout << endl;
	cout << " ~ Message (hex)" << endl;
	for (auto val : message) printf("%.2x", val);
	cout << endl;

	// CMAC tag
	std::vector<unsigned char> cmac_tag = generate_AES_CMAC(message, key);
	cout << " ~ Message's CMAC tag (hex)" << endl;
	for (auto val : cmac_tag) printf("%.2x", val);
	cout << endl;

	// Test result
	cout << "Test: ";
	if (validate_AES_CMAC(message, key, cmac_tag)) {
		cout << "PASSED";
	} else {
		cout << "FAILED";
	}
	cout << endl << endl;
}
