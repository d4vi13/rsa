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

void task4() {
  /* Task 4: Signing a Message*/
  char M1[] = "I owe you $2000.";
  char M2[] = "I owe you $3000.";
  char n[] = "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5";
  char e[] = "010001";
  char d[] = "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D";
  key_pair_t *kp;
  BIGNUM *signature;

  if (!(kp = hex_create_key_pair(n, e, d))) goto err_create_key;
  if (!(signature = encrypt_ascii(&kp->private_key, M1))) goto err_enc;

  printf("M1=%s\n", M1);
  printBN("signature=", signature);

  if (!(signature = encrypt_ascii(&kp->private_key, M2))) goto err_enc;

  printf("M2=%s\n", M2);
  printBN("signature=", signature);

  BN_free(signature);
err_enc:
  free_key_pair(kp);
err_create_key:
  return;
}

void task5() {
  /* Task 5: Verifying a Signature*/
  char M[] = "Launch a missile";
  char S[] = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F";
  // fake signature
  char F[] = "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F";
  char n[] = "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115";
  char e[] = "010001";
  key_pair_t *kp;
  char *plain;

  if (!(kp = hex_create_key_pair(n, e, NULL))) goto err_create_key;
  if (!(plain = decrypt_hex(&kp->public_key, S))) goto err_enc;

  printf("original=%s\n", M);

  printf("signature S=%s\n", S);
  printf("hex dec(signature S)=0x%s\n", plain);
  print_ascii_from_hex("plain dec(signature S)=%s\n", plain);

  if (!(plain = decrypt_hex(&kp->public_key, F))) goto err_enc;

  printf("signature F=%s\n", S);
  printf("hex dec(signature S)=0x%s\n", plain);
  printf("unable to print plain text, corrupts everything");


  free(plain);
err_enc:
  free_key_pair(kp);
err_create_key:
  return;
}
int main() {
  BIGNUM *phi;

  init_rsa();

  //task1();
  //task2();
  //task3();
  //task4();
  task5();

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
