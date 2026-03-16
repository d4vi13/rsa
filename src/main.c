#include "tasks.h"

int main() {
  init_rsa();

  printf("\nTask 1: Deriving the Private Key -----------------------------------\n\n");
  task1();

  printf("\nTask 2: Encrypting a Message ---------------------------------------\n\n");
  task2();

  printf("\nTask 3: Decrypting a Message ---------------------------------------\n\n");
  task3();

  printf("\nTask 4: Signing a Message ------------------------------------------\n\n");
  task4();

  printf("\nTask 5: Verifying a Signature -------------------------------------\n\n");
  task5();

  finish_rsa();
  
  return 0;
}
