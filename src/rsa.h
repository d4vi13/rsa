#ifndef RSA_H
#define RSA_H

#include "common.h"

typedef struct {
  BIGNUM *mod;
  BIGNUM *exp;
} rsa_key_t;

typedef struct {
  rsa_key_t private_key;
  rsa_key_t public_key;
} key_pair_t;

void print_key(char *msg, rsa_key_t *k);

void printBN(char *msg, BIGNUM * a);

void print_ascii_from_hex(char *fmt, char *hex);

int init_rsa();

void finish_rsa();

void free_key_pair(key_pair_t *kp);

key_pair_t *derive_key_pair (BIGNUM *p, BIGNUM *q, BIGNUM *e);

BIGNUM *encrypt_ascii(rsa_key_t *key, char *msg);

BIGNUM *encrypt(rsa_key_t *key, BIGNUM *msg);

BIGNUM *decrypt(rsa_key_t *key, BIGNUM *msg);

char *decrypt_hex(rsa_key_t *key, char *hex);

key_pair_t *hex_create_key_pair(char *mod_hex, char *enc_hex, char *dec_hex);

key_pair_t *create_key_pair(BIGNUM *mod, BIGNUM *enc, BIGNUM *dec);
#endif
