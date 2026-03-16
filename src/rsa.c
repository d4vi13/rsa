#include "rsa.h"

// TODO init lib and create global ctx for bn

void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s %s\n", msg, number_str);
  OPENSSL_free(number_str);
}

BN_CTX *ctx;

int init_rsa () {
  errno = 0;
  if (!(ctx = BN_CTX_new())) goto error;

  return 0;
error:

  return 1;
}

BIGNUM *compute_phi_from_factors(BIGNUM *p, BIGNUM *q) {
  errno = 0;
  BIGNUM *prev_q, *prev_p,*one, *res;

  if (!(prev_q = BN_new())) goto err_prev_q;
  if (!(prev_p = BN_new())) goto err_prev_p;
  if (!(res = BN_new())) goto err_res;
  if (!(one = BN_new())) goto err_one;

  if (!BN_dec2bn(&one, "1")) goto err_op;
  if (!BN_sub(prev_p, p, one)) goto err_op;
  if (!BN_sub(prev_q, q, one)) goto err_op;
  if (!BN_mul(res, prev_p, prev_q, ctx)) goto err_op;

  return res;

err_op:
err_one:
  BN_free(one);
err_res:
  BN_free(res);
err_prev_p:
  BN_free(prev_p);
err_prev_q:
  BN_free(prev_q);

  perror("failed to compute phi");
  return NULL;
}

key_pair_t *derive_key_pair (BIGNUM *p, BIGNUM *q, BIGNUM *e) {
  errno = 0;
  key_pair_t *key_pair; 
  BIGNUM *mod, *phi, *d;

  if (!(mod = BN_new())) goto err_mod;
  if (!(d = BN_new())) goto err_d;

  if (!(key_pair = calloc(1, sizeof * key_pair))) {
    perror("failed to alloc key pair");
    goto err_failed_alloc;
  }

  if (!(phi = compute_phi_from_factors(p, q))) goto err_op_failed;
  if (!BN_mul(mod, p, q, ctx)) goto err_phi;
  if (!BN_mod_inverse(d, e, phi, ctx)) goto err_phi;

  key_pair->public_key.mod = mod;
  key_pair->public_key.exp = e;

  key_pair->private_key.mod = mod;
  key_pair->private_key.exp = d;

  BN_free(phi);
  return key_pair;

err_phi:
  BN_free(phi);
err_op_failed: 
  free(key_pair);
err_d:
  BN_free(d);
err_mod:
  BN_free(mod);

err_failed_alloc:

  perror("failed to derive key pair");
  return NULL;
}

char *ascii2hex(char *msg) {
  errno = 0;
  size_t len = strlen(msg);
  char *hex = calloc(2 * len, sizeof * hex);

  if (!hex) return NULL;
 
  for (size_t i = 0; i < len; i++) {
    sprintf(hex+2*i, "%02x", msg[i]);
  }

  return hex;
}

static inline BIGNUM *rsa(rsa_key_t *key, BIGNUM *text) {
  BIGNUM *res;

  if (!(res = BN_new())) goto err;

  if (BN_mod_exp(res, text, key->exp, key->mod, ctx))
    return res;

   BN_free(res);
err:
    return NULL;
}

BIGNUM *encrypt(rsa_key_t *key, BIGNUM *plain_text) {
  return rsa(key, plain_text);
}

BIGNUM *decrypt(rsa_key_t *key, BIGNUM *cipher_text) {
  return rsa(key, cipher_text);
}

BIGNUM *encrypt_ascii(rsa_key_t *key, char *msg) {
  errno = 0;
  char *hex;
  BIGNUM *num, *cipher;

  if (!(num = BN_new())) goto err_num;

  if (!(hex = ascii2hex(msg))) {
    perror("failed to convert ascii str to hex");
    goto err_hex;
  }

  if (!BN_hex2bn(&num, hex)) goto err;
  if (!(cipher = encrypt(key, num))) goto err;

  free(hex);
  return cipher;
  
err:
  free(hex);
err_hex:
  BN_free(num);
err_num:

  perror("failed to encrypt asciit text");
  return NULL;
}

void hex2ascii(char *hex) {
   
}

BIGNUM *decrypt_hex(rsa_key_t *key, char *hex) {
  BIGNUM *plain, *conv = BN_new();
  char *plain_hex;

  BN_hex2bn(&conv, hex);

  plain = decrypt (key, conv);
  plain_hex = BN_bn2hex(plain);


}
