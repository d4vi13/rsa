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

struct context {
  key_pair_t key_pair;
};

int init_rsa();
BIGNUM *compute_phi_from_factors(BIGNUM *p, BIGNUM *q);
// int generate_key_pair ();

key_pair_t *derive_key_pair (BIGNUM *p, BIGNUM *q, BIGNUM *e);

void printBN(char *msg, BIGNUM * a);
#endif
