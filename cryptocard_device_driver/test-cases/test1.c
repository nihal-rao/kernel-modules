#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>

int main()
{
  DEV_HANDLE cdev;
  char *msg = "Hello CS730!";
  char op_text[16];
  KEY_COMP a=30, b=17;
  uint64_t size = strlen(msg);
  strcpy(op_text, msg);
  cdev = create_handle();

  if(cdev == ERROR)
  {
    printf("Unable to create handle for device\n");
    exit(0);
  }
//uint64_t size = strlen(msg)
 set_config(cdev, DMA, 0);   // MMAP only valid in MMIO mode
  set_config(cdev, INTERRUPT, 1); // This test case is w/o interrupts 
  set_key(cdev, a, b);
  char *actual_buff = map_card(cdev, size);   // Return a pointer mapped to the device memory
  strncpy(actual_buff, msg, size);
  encrypt(cdev, actual_buff, size, 1);   // Last argument is 1 ==> it is mapped
  //At this point, "actual_buf" contains the encrypted message
  printf("actual buff is %s\n", actual_buff);
  decrypt(cdev, actual_buff, size, 1);
  printf("actual buff is %s\n", actual_buff);
  unmap_card(cdev, actual_buff);
  close_handle(cdev);
  
	/*if(set_key(cdev, a, b) == ERROR){
    printf("Unable to set key\n");
    exit(0);
  }


if(set_config(cdev, DMA, UNSET) == ERROR){
    printf("Unable to set config\n");
	exit(0);
}

if(set_config(cdev, INTERRUPT, SET) == ERROR){
    printf("Unable to set config\n");
    exit(0);
}

  printf("Original Text: %s\n", msg);

  encrypt(cdev, op_text, size, 0);
  printf("Encrypted Text: %s\n", op_text);

  decrypt(cdev, op_text, size, 0);
  printf("Decrypted Text: %s\n", op_text);

  close_handle(cdev);*/
  return 0;
}
