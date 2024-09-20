#include <stdio.h>
#include <stdlib.h>
#include <secp256k1.h>
#include <string.h>

void generate_public_key(unsigned char *private_key) {
    // Create a context for secp256k1
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    // Output public key
    secp256k1_pubkey pubkey;e

    // Generate the public key
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        printf("Error: Public key generation failed.\n");
        secp256k1_context_destroy(ctx);
        return;
    }

    // Serialize the public key
    unsigned char output[65];
    size_t output_length = sizeof(output);
    secp256k1_ec_pubkey_serialize(ctx, output, &output_length, &pubkey, SECP256K1_EC_UNCOMPRESSED);

    // Print the public key in hexadecimal format
    printf("Public Key: ");
    for (int i = 0; i < output_length; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");

    // Destroy the context
    secp256k1_context_destroy(ctx);
}

int main() {
    // Example private key (32 bytes)
    unsigned char private_key[32] = {
        0x1E, 0x99, 0xF9, 0xB8, 0xFA, 0x6F, 0x55, 0xA2, 
        0xD1, 0x7E, 0xFC, 0xC8, 0x74, 0x9F, 0x7A, 0x95,
        0x6A, 0x1B, 0x6F, 0x5A, 0x12, 0x7F, 0x29, 0x43,
        0x9E, 0x0D, 0xF7, 0xC4, 0x92, 0xFA, 0xAA, 0x55
    };

    // Generate and print the public key
    generate_public_key(private_key);

    return 0;
}
