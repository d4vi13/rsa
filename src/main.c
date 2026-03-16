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

void task1() {
  /* Task 1: Deriving the Private Key */
  key_pair_t *kp;
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();

  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");

  if (!(kp = derive_key_pair(p, q, e))) {
    perror("failed to derive key pair");
    goto err;
  }

  print_key("public_key=", &kp->public_key);
  print_key("private_key=", &kp->private_key);

  free_key_pair(kp);
err:
  BN_free(p);
  BN_free(q);
  BN_free(e);
  return;
}

// TODO look for the 2 missing frees
void task2() {
  /* Task 2: Encrytpting a Message */
  char M[] = "A top secret!";
  char n[] = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
  char e[] = "010001";
  char d[] = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
  key_pair_t *kp;
  BIGNUM *cipher;

  if (!(kp = hex_create_key_pair(n, e, d))) goto err_create_key;
  if (!(cipher = encrypt_ascii(&kp->public_key, M))) goto err_enc;

  printBN("cipher=", cipher);

  BN_free(cipher);
err_enc:
  free_key_pair(kp);
err_create_key:
  return;
}

void task3() {
  /* Task 3: Decrypting a Message */
  char C[] = "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F";
  char n[] = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
  char e[] = "010001";
  char d[] = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
  key_pair_t *kp;
  char *plain;

  if (!(kp = hex_create_key_pair(n, e, d))) goto err_create_key;
  if (!(plain = decrypt_hex(&kp->private_key, C))) goto err_dec;

  print_ascii_from_hex("plain=%s\n", plain);

  free(plain);
err_dec:
  free_key_pair(kp);
err_create_key:
  return;
}

int main() {
  BIGNUM *phi;

  init_rsa();

  //task1();
  //task2();
  task3();

  finish_rsa();

  return 0;
  
  BIGNUM *p = BN_new();
  BIGNUM *q = BN_new();
  BIGNUM *e = BN_new();

  BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
  BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
  BN_hex2bn(&e, "0D88C3");
  BN_hex2bn(&e, "010001");

  /*
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DE");
  BN_hex2bn(&q, "");
  BN_hex2bn(&e, "010001");
  */
  BN_hex2bn(&p, "B");
  BN_hex2bn(&q, "D");
  BN_hex2bn(&e, "11");



  key_pair_t *kp = derive_key_pair(p, q, e); 

  printBN("phi: ", phi);
  printBN("public mod ", kp->public_key.mod);
  printBN("public exp ", kp->public_key.exp);
  printBN("private mod ", kp->private_key.mod);
  printBN("private exp ", kp->private_key.exp);


  //BN_hex2bn(&kp->public_key.mod, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
  BIGNUM *c = encrypt_ascii(&kp->public_key, "X");
  /*BIGNUM *plain = BN_new();
  BN_dec2bn(&plain, "88"); 
  BIGNUM *c = encrypt(&kp->public_key, plain);
  */

  printBN("cipher ", c);

  BIGNUM *d = decrypt(&kp->private_key, c);
  printBN("plain ", d);

  return 0;
}
