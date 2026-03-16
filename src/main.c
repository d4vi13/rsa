/*  
#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256



int main ()
{

  

  BN_CTX *ctx = BN_CTX_new();

  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *n = BN_new();
  BIGNUM *res = BN_new();


  // Initialize a, b, n
  BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
  BN_dec2bn(&b, "273489463796838501848592769467194369268");
  BN_rand(n, NBITS, 0, 0);

  // res = a*b
  BN_mul(res, a, b, ctx);
  printBN("a * b = ", res);

  // res = a^b mod n
  BN_mod_exp(res, a, b, n, ctx);
  printBN("a^c mod n = ", res);

  return 0;
}
*/

#include "rsa.h"
#include "common.h"


int main() {
  BIGNUM *phi;
  init_rsa();

  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();

  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  /*
  BN_hex2bn(&p, "B");
  BN_hex2bn(&q, "D");
  BN_hex2bn(&e, "11");

  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DE");
  BN_hex2bn(&q, "");
  BN_hex2bn(&e, "010001");
  */

  phi = compute_phi_from_factors(p, q);

  key_pair_t *kp = derive_key_pair(p, q, e); 

  printBN("phi: ", phi);
  printBN("public mod ", kp->public_key.mod);
  printBN("public exp ", kp->public_key.exp);
  printBN("private mod ", kp->private_key.mod);
  printBN("private exp ", kp->private_key.exp);



  return 0;
}
