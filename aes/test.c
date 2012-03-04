#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define UNDER_TEST 1
#include "aes.h"

#define TEST_THAT(d,f)    { \
        printf("Test that " d "..."); \
        f(); \
        printf(" ok\n"); \
}

void print_hex(uint8_t *xs) {
    int i, j;
    for (i = 0; i < 16; i+=4) {
        for (j = 0; j < 4; j++) {
            printf("%02x ", xs[i + j]);
        }
        printf("\n");
    }
}

void test_expand_key() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    uint8_t expected[] = 
            "\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x31\x32\x33\x34\x35"
            "\x8a\x7d\xfa\x4f\xe5\x5d\x8d\x20\x97\x31\xe9\x11\xa5\x02\xdd\x24"
            "\xff\xbc\xcc\x49\x1a\xe1\x41\x69\x8d\xd0\xa8\x78\x28\xd2\x75\x5c"
            "\x4e\x21\x86\x7d\x54\xc0\xc7\x14\xd9\x10\x6f\x6c\xf1\xc2\x1a\x30"
            "\x63\x83\x82\xdc\x37\x43\x45\xc8\xee\x53\x2a\xa4\x1f\x91\x30\x94"
            "\xf2\x87\xa0\x1c\xc5\xc4\xe5\xd4\x2b\x97\xcf\x70\x34\x06\xff\xe4"
            "\xbd\x91\xc9\x04\x78\x55\x2c\xd0\x53\xc2\xe3\xa0\x67\xc4\x1c\x44"
            "\xe1\x0d\xd2\x81\x99\x58\xfe\x51\xca\x9a\x1d\xf1\xad\x5e\x01\xb5"
            "\x39\x71\x07\x14\xa0\x29\xf9\x45\x6a\xb3\xe4\xb4\xc7\xed\xe5\x01"
            "\x77\xa8\x7b\xd2\xd7\x81\x82\x97\xbd\x32\x66\x23\x7a\xdf\x83\x22"
            "\xdf\x44\xe8\x08\x08\xc5\x6a\x9f\xb5\xf7\x0c\xbc\xcf\x28\x8f\x9e";
    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    assert(memcmp(expected, aes.expanded_key, sizeof(expected) - 1) == 0);
}

void test_sub_bytes() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    uint8_t state[] = 
            "1234"
            "5678"
            "9012"
            "3456";
    uint8_t expected[] = 
            "\xc7\x23\xc3\x18"
            "\x96\x05\x9a\x07"
            "\x12\x04\xc7\x23"
            "\xc3\x18\x96\x05";

    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    memcpy(aes.state, state, sizeof(state) - 1);

    sub_bytes(&aes);

    assert(memcmp(expected, aes.state, sizeof(expected) - 1) == 0);
}

void test_shift_rows() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    uint8_t state[] = 
            "1234"
            "5678"
            "9012"
            "3456";
    uint8_t expected[] = 
            "1234"
            "6785"
            "1290"
            "6345";
    
    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    memcpy(aes.state, state, sizeof(state) - 1);

    shift_rows(&aes);

    assert(memcmp(expected, aes.state, sizeof(expected) - 1) == 0);
}

void test_mix_columns() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    // from wikipedia's examples
    uint8_t state[] = 
            "\xdb\xf2\x01\xc6"
            "\x13\x0a\x01\xc6"
            "\x53\x22\x01\xc6"
            "\x45\x5c\x01\xc6";
    uint8_t expected[] = 
            "\x8e\x9f\x01\xc6"
            "\x4d\xdc\x01\xc6"
            "\xa1\x58\x01\xc6"
            "\xbc\x9d\x01\xc6";
    
    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    memcpy(aes.state, state, sizeof(state) - 1);

    mix_columns(&aes);

    assert(memcmp(expected, aes.state, sizeof(expected) - 1) == 0);
}

void test_add_round_key_0() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    uint8_t state[] = 
            "1234"
            "5678"
            "9012"
            "3456";
    uint8_t expected[] = 
            "\x79\x57\x5f\x58"
            "\x5a\x16\x40\x57"
            "\x4b\x5c\x55\x03"
            "\x01\x07\x01\x03";
    
    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    memcpy(aes.state, state, sizeof(state) - 1);

    add_round_key(&aes, 0);

    assert(memcmp(expected, aes.state, sizeof(expected) - 1) == 0);
}

void test_add_round_key_1() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    uint8_t state[] = 
            "1234"
            "5678"
            "9012"
            "3456";
    uint8_t expected[] = 
            "\xbb\x4f\xc9\x7b"
            "\xd0\x6b\xba\x18"
            "\xae\x01\xd8\x23"
            "\x96\x36\xe8\x12";
    
    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    memcpy(aes.state, state, sizeof(state) - 1);

    add_round_key(&aes, 1);

    assert(memcmp(expected, aes.state, sizeof(expected) - 1) == 0);
}

void test_add_round_key_10() {
    aes_t aes;
    uint8_t key[] = "Hello world12345";
    uint8_t state[] = 
            "1234"
            "5678"
            "9012"
            "3456";
    uint8_t expected[] = 
            "\xee\x76\xdb\x3c"
            "\x3d\xf3\x5d\xa7"
            "\x8c\xc7\x3d\x8e"
            "\xfc\x1c\xba\xa8";
    
    aes_init(&aes, AES_128, key, sizeof(key) - 1);
    memcpy(aes.state, state, sizeof(state) - 1);

    add_round_key(&aes, 10);

    assert(memcmp(expected, aes.state, sizeof(expected) - 1) == 0);
}

int main() {
    TEST_THAT("expand key works", test_expand_key);
    TEST_THAT("sub bytes works", test_sub_bytes);
    TEST_THAT("shift rows works", test_shift_rows);
    TEST_THAT("mix columns works", test_mix_columns);
    TEST_THAT("add round key 0 works", test_add_round_key_0);
    TEST_THAT("add round key 1 works", test_add_round_key_1);
    TEST_THAT("add round key 10 works", test_add_round_key_10);
    return 0;
}
