#include "rsa.h"

/* globals ------------------------------------------------------------------*/

BN_CTX *ctx;

/* print utils --------------------------------------------------------------*/

/* print a big num */
void printBN(char *msg, BIGNUM * a)
{
  char * number_str = BN_bn2hex(a);
  printf("%s%s\n", msg, number_str);
  OPENSSL_free(number_str);
}

/* print the components of a key*/
void print_key(char *msg, rsa_key_t *k)
{
  char *mod = BN_bn2hex(k->mod);
  char *exp = BN_bn2hex(k->exp);

  printf("%s(e=%s, n=%s)\n", msg, exp, mod);

  OPENSSL_free(mod);
  OPENSSL_free(exp);
}

/* print a err string from openssl lib */
void print_ssl_err() {
  char err_string[256];
  unsigned long err_code;

  err_code = ERR_get_error();
  ERR_error_string(err_code, err_string);

  fprintf(stderr, "%s\n", err_string);

  return;
}

/* print ascii from hexadecimal string */
void print_ascii_from_hex(char *fmt, char *hex) {
    size_t len = strlen(hex);
    size_t byte_len = len / 2;
    unsigned char *bytes = malloc(byte_len + 1);

    for (size_t i = 0; i < byte_len; i++) 
        sscanf(hex + 2*i, "%2hhx", &bytes[i]); // hh is for some size bs
    bytes[byte_len] = '\0'; 

    printf(fmt, (char*)bytes);

    free(bytes);
}

/* intialization ------------------------------------------------------------*/

int init_rsa () {
  errno = 0;
  if (!(ctx = BN_CTX_new())) goto error;

  return 0;
error:

  return 1;
}

void finish_rsa () {
  BN_CTX_free(ctx);

  return;
}

void free_rsa_key(rsa_key_t *key) {
  BN_free(key->mod);
  BN_free(key->exp);

  return;
}

void free_key_pair(key_pair_t *kp) {
  free_rsa_key(&kp->public_key);
  free_rsa_key(&kp->private_key);
  free(kp);

  return;
}

/* helpers ------------------------------------------------------------------*/

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

/* keys ---------------------------------------------------------------------*/

static BIGNUM *compute_phi_from_factors(BIGNUM *p, BIGNUM *q) {
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

  BN_free(one);
  BN_free(prev_p);
  BN_free(prev_q);
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

  if (!(key_pair = calloc(1, sizeof * key_pair))) goto err_failed_alloc;
  if (!(phi = compute_phi_from_factors(p, q))) goto err_op_failed;
  if (!BN_mul(mod, p, q, ctx)) goto err_phi;
  if (!BN_mod_inverse(d, e, phi, ctx)) goto err_phi;

  key_pair->public_key.mod = mod;
  key_pair->public_key.exp = BN_dup(e); 

  key_pair->private_key.mod = BN_dup(mod);
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


key_pair_t *create_key_pair(BIGNUM *mod, BIGNUM *enc, BIGNUM *dec) {
  key_pair_t *kp;

  if (!(kp = calloc(1, sizeof * kp))) return NULL;

  kp->public_key.mod = mod;
  kp->public_key.exp = enc; 

  kp->private_key.mod = BN_dup(mod);
  kp->private_key.exp = dec;

  return kp;
}

key_pair_t *hex_create_key_pair(char *mod_hex, char *enc_hex, char *dec_hex) {
  BIGNUM *mod = NULL, *enc = NULL, *dec = NULL;
  key_pair_t *kp;

  if (!(mod = BN_new())) goto err_mod;
  if (!(enc = BN_new())) goto err_enc;
  if (!(dec = BN_new())) goto err_dec;

  if (mod_hex && !BN_hex2bn(&mod, mod_hex)) goto err_conv;
  if (enc_hex && !BN_hex2bn(&enc, enc_hex)) goto err_conv;
  if (dec_hex && !BN_hex2bn(&dec, dec_hex)) goto err_conv;

  if (!(kp = create_key_pair(mod, enc, dec))) goto err_kp;

  return kp;

err_conv:
err_kp:
  free(dec);
err_dec:
  BN_free(enc);
err_enc:
  BN_free(mod);
err_mod:
  return NULL;
}

/* rsa ----------------------------------------------------------------------*/

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

char *decrypt_hex(rsa_key_t *key, char *hex) {
  BIGNUM *plain, *cipher;
  char *plain_hex;

  if (!(cipher = BN_new())) goto fail;
  if (!BN_hex2bn(&cipher, hex)) goto free_cipher;
  if (!(plain = decrypt (key, cipher))) goto free_cipher;
  if (!(plain_hex = BN_bn2hex(plain))) goto free_plain;

  free(cipher);
  free(plain);
  return plain_hex;

free_plain:
  BN_free(plain);
free_cipher:
  BN_free(cipher);
fail:
  return NULL;
}
