#include <string.h>
#include "../include/facekid.h"

#define Nb 4  // number of columns
#define Nk 4  // number of 32-bit words in key
#define Nr 10 // number of rounds

// AES S-box
static const unsigned char sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
};

// Inverse S-box
static const unsigned char inv_sbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
};

// Helper functions
static void add_round_key(unsigned char *state, unsigned char *round_key) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= round_key[i];
	}
}

static void sub_bytes(unsigned char *state) {
	for (int i = 0; i < 16; i++) {
		state[i] = sbox[state[i]];
	}
}

static void inv_sub_bytes(unsigned char *state) {
	for (int i = 0; i < 16; i++) {
		state[i] = inv_sbox[state[i]];
	}
}

static void shift_rows(unsigned char *state) {
	unsigned char temp;
	
	// Row 1: shift left by 1
	temp = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = temp;
	
	// Row 2: shift left by 2
	temp = state[2];
	state[2] = state[10];
	state[10] = temp;
	temp = state[6];
	state[6] = state[14];
	state[14] = temp;
	
	// Row 3: shift left by 3
	temp = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = temp;
}

static void inv_shift_rows(unsigned char *state) {
	unsigned char temp;
	
	// Row 1: shift right by 1
	temp = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = temp;
	
	// Row 2: shift right by 2
	temp = state[2];
	state[2] = state[10];
	state[10] = temp;
	temp = state[6];
	state[6] = state[14];
	state[14] = temp;
	
	// Row 3: shift right by 3
	temp = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = temp;
}

void aes_cipher(char *text, char *key) {
	unsigned char state[16];
	unsigned char expanded_key[176];
	
	// Copy input to state array
	memcpy(state, text, 16);
	
	// Key expansion (simplified for this example)
	memcpy(expanded_key, key, 16);
	
	// Initial round
	add_round_key(state, expanded_key);
	
	// Main rounds
	for (int round = 1; round < Nr; round++) {
		sub_bytes(state);
		shift_rows(state);
		// mix_columns(state); // Omitted for simplicity
		add_round_key(state, expanded_key + round * 16);
	}
	
	// Final round
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, expanded_key + Nr * 16);
	
	// Copy result back to text
	memcpy(text, state, 16);
}

void aes_decode(char *cipher_text, char *key) {
	unsigned char state[16];
	unsigned char expanded_key[176];
	
	// Copy input to state array
	memcpy(state, cipher_text, 16);
	
	// Key expansion (simplified for this example)
	memcpy(expanded_key, key, 16);
	
	// Initial round
	add_round_key(state, expanded_key + Nr * 16);
	
	// Main rounds
	for (int round = Nr - 1; round > 0; round--) {
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, expanded_key + round * 16);
		// inv_mix_columns(state); // Omitted for simplicity
	}
	
	// Final round
	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, expanded_key);
	
	// Copy result back to cipher_text
	memcpy(cipher_text, state, 16);
}