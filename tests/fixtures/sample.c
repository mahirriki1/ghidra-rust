/* Small, source-controlled analysis fixture. No external application code. */
#include <stddef.h>
#include <stdio.h>

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

const char base64_message[] = "aGVsbG8gcmV2ZXJzZXI=";
const unsigned char xor_message[] = {0x59, 0x4f, 0x49, 0x58, 0x4f, 0x5e};

/* First 64 entries of the standardized AES substitution table (FIPS 197).
 * Volatile accesses retain the table even in an optimized build. */
const volatile unsigned char aes_sbox_prefix[64] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
};

volatile unsigned int fixture_sink;

NOINLINE unsigned int branch_loop(unsigned int count) {
    unsigned int total = 0;
    for (unsigned int index = 0; index < count; ++index) {
        if (index & 1) {
            total += index * 3;
        } else {
            total ^= index + 7;
        }
    }
    return total;
}

NOINLINE void decode_xor(char *output) {
    for (size_t index = 0; index < sizeof(xor_message); ++index) {
        output[index] = (char)(xor_message[index] ^ 0x2a);
    }
    output[sizeof(xor_message)] = '\0';
}

int main(int argc, char **argv) {
    (void)argv;
    char decoded[sizeof(xor_message) + 1];
    decode_xor(decoded);
    puts(base64_message);
    puts(decoded);
    fixture_sink = branch_loop((unsigned int)argc + 5);
    for (size_t index = 0; index < sizeof(aes_sbox_prefix); ++index) {
        fixture_sink += aes_sbox_prefix[index];
    }
    return 0;
}
