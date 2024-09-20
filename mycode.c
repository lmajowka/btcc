#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

// Base58 alphabet for encoding
const char* base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Function to perform SHA-256
void sha256(const unsigned char* data, size_t len, unsigned char* output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, len);
    SHA256_Final(output, &sha256);
}

// Function to perform RIPEMD-160
void ripemd160(const unsigned char* data, size_t len, unsigned char* output) {
    RIPEMD160_CTX ripemd;
    RIPEMD160_Init(&ripemd);
    RIPEMD160_Update(&ripemd, data, len);
    RIPEMD160_Final(output, &ripemd);
}

// Function to perform Base58Check encoding
void base58_encode(const unsigned char* input, size_t input_len, char* output) {
    unsigned char digits[50] = {0};
    size_t digit_len = 1;
    
    for (size_t i = 0; i < input_len; i++) {
        int carry = input[i];
        for (size_t j = 0; j < digit_len; j++) {
            carry += 256 * digits[j];
            digits[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits[digit_len++] = carry % 58;
            carry /= 58;
        }
    }

    int leading_zeroes = 0;
    while (leading_zeroes < input_len && input[leading_zeroes] == 0) {
        output[leading_zeroes++] = '1';
    }

    for (size_t i = 0; i < digit_len; i++) {
        output[leading_zeroes + i] = base58_alphabet[digits[digit_len - 1 - i]];
    }
    output[leading_zeroes + digit_len] = '\0';
}

// Function to generate Bitcoin address from the public key
void generate_bitcoin_address(const unsigned char* public_key, size_t public_key_len) {
    printf("Public key: ");
    for (size_t i = 0; i < public_key_len; i++) {
        printf("%02x", public_key[i]);
    }
    printf("\n");
    
    // Step 1: Perform SHA-256 on the public key
    unsigned char sha256_hash[32];
    sha256(public_key, public_key_len, sha256_hash);

    // Step 2: Perform RIPEMD-160 on the SHA-256 hash
    unsigned char ripemd160_hash[20];
    ripemd160(sha256_hash, 32, ripemd160_hash);

    // Step 3: Add version byte (0x00 for mainnet) to create payload
    unsigned char versioned_payload[21];
    versioned_payload[0] = 0x00;  // Version byte for mainnet
    memcpy(versioned_payload + 1, ripemd160_hash, 20);

    // Step 4: Perform double SHA-256 on the versioned payload
    unsigned char double_sha256[32];
    sha256(versioned_payload, 21, double_sha256);
    sha256(double_sha256, 32, double_sha256);  // Double SHA-256

    // Step 5: Append first 4 bytes of double SHA-256 as checksum
    unsigned char address_bytes[25];
    memcpy(address_bytes, versioned_payload, 21);
    memcpy(address_bytes + 21, double_sha256, 4);  // Add checksum

    // Step 6: Encode address bytes in Base58Check
    char bitcoin_address[50];
    base58_encode(address_bytes, 25, bitcoin_address);

    // Output the Bitcoin address
    printf("Bitcoin Address: %s\n", bitcoin_address);
}

int main() {
    // Example private key (32 bytes)
    unsigned char private_key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x83, 0x2E, 0xD7, 0x4F, 0x2B, 0x5E, 0x35, 0xEE
    };

    // Step 1: Initialize secp256k1 context
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

   // Print the private key in hex format
    print_private_key(private_key, sizeof(private_key));

    // Step 2: Generate public key from private key
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        printf("Error: Public key generation failed.\n");
        secp256k1_context_destroy(ctx);
        return -1;
    }

    // Step 3: Serialize the public key (uncompressed format)
    unsigned char pubkey_serialized[65];
    size_t pubkey_len = sizeof(pubkey_serialized);
    secp256k1_ec_pubkey_serialize(ctx, pubkey_serialized, &pubkey_len, &pubkey, SECP256K1_EC_COMPRESSED);

    // Generate Bitcoin address from the serialized public key
    generate_bitcoin_address(pubkey_serialized, pubkey_len);

    // Clean up secp256k1 context
    secp256k1_context_destroy(ctx);

    return 0;
}


void print_private_key(const unsigned char* private_key, size_t key_len) {
    printf("Private key: ");
    for (size_t i = 0; i < key_len; i++) {
        printf("%02x", private_key[i]);
    }
    printf("\n");
}