#include "rsa.h"

// TODO init lib and create global ctx for bn

BN_CTX *ctx;

int init_rsa () {
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

  if (!BN_dec2bn(&one, "1")) goto error_op;
  if (!BN_sub(prev_p, p, one)) goto error_op;
  if (!BN_sub(prev_q, q, one)) goto error_op;
  if (!BN_mul(res, prev_p, prev_q, ctx)) goto error_op;

  return res;

error_op:
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
  BIGNUM *mod, *phi, *d = NULL;

  if (!(mod = BN_new())) goto err_mod;
  
  if (!(key_pair = calloc(1, size * key_pair))) {
    perror("failed to alloc key pair");
    goto err_failed_alloc;
  }

  if (!(phi = compute_phi_from_factors(p, q))) goto err_op_failed;
  if (!BN_mul(mod, p, q, ctx)) goto err_op_failed;
  if (!BN_mod_inverse(d, e, phi, ctx)) goto err_op_failed;

  key_pair.public_key = {
    .mod = mod,
    .exp = e
  };

  key_pair.private_key = {
    .mod = mod,
    .exp = d
  };

  BN_free(phi);
  return key_pair;

err_op_failed: 
  free(key_pair);
err_mod:
  BN_free(mod);
  BN_free(phi);
 
err_failed_alloc:
  return NULL;
}

