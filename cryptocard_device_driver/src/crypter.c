#include <crypter.h>
#include <assert.h>
#include <string.h>
#include <math.h>
#include <sys/mman.h>
/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{
  int fd = open("/dev/cs614_device", O_RDWR);
  if (fd >= 0)
  {
    return fd;
  }
  else
  {
    return ERROR;
  }
}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
  close(cdev);
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  // 0 is for encrypt
  if (!isMapped)
  {
    uint64_t av_length = 4096 - 3; // to avoid any overflows
    uint64_t length_copy = length;
    uint64_t ctr = 0;
    while (length > 0)
    {
      uint64_t curr_length = length > av_length ? av_length : length;
      char msg[curr_length + 1];
      // printf("current length is %ld\n", curr_length);
      strncpy(msg + 1, (char *)addr + ctr, curr_length);
      msg[0] = '0';
      int ret;
      ret = write(cdev, msg, curr_length + 1);
      // printf("write() ret: %d\n", ret);
      ret = read(cdev, addr + ctr, curr_length);
      // assert(ret > 0);
      length -= curr_length;
      ctr += curr_length;
    }
    // assert(ctr==length_copy);
    return length_copy;
  }
  else
  {
    char msg[10];
    char num[10];
    msg[0] = '5';
    uint64_t length_copy = length;
    int n = 0;
    while (length > 0)
    {
      num[n] = 48 + (length % 10);
      length = length / 10;
      n++;
    }
    int i = 0;
    while (i < n / 2)
    {
      char x = num[i];
      num[i] = num[n - i - 1];
      num[n - 1 - i] = x;
      i++;
    }
    num[n] = '\0';
    // printf("num is %s\n", num);
    strncpy(msg + 1, num, n);
    int ret;
    ret = write(cdev, msg, n + 1);
    return length_copy;
  }
}

/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  // 1 is for decrypt
  if (!isMapped)
  {
    uint64_t av_length = 4096 - 3; // to avoid any overflows
    uint64_t length_copy = length;
    uint64_t ctr = 0;
    while (length > 0)
    {
      uint64_t curr_length = length > av_length ? av_length : length;
      char msg[curr_length + 1];
      // printf("current length is %ld\n", curr_length);
      strncpy(msg + 1, (char *)addr + ctr, curr_length);
      msg[0] = '1';
      int ret;
      ret = write(cdev, msg, curr_length + 1);
      // printf("write() ret: %d\n", ret);
      ret = read(cdev, addr + ctr, curr_length);
      // assert(ret > 0);
      length -= curr_length;
      ctr += curr_length;
    }
    // assert(ctr==length_copy);
    return length_copy;
  }
  else
  {
    char msg[10];
    char num[10];
    msg[0] = '6';
    uint64_t length_copy = length;
    int n = 0;
    while (length > 0)
    {
      num[n] = 48 + (length % 10);
      length = length / 10;
      n++;
    }
    int i = 0;
    while (i < n / 2)
    {
      char x = num[i];
      num[i] = num[n - i - 1];
      num[n - 1 - i] = x;
      i++;
    }
    num[n] = '\0';
    // printf("num is %s\n", num);
    strncpy(msg + 1, num, n);
    int ret;
    ret = write(cdev, msg, n + 1);
    return length_copy;
  }
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
  unsigned char msg[4];
  msg[0] = '2';
  msg[1] = a;
  msg[2] = b;
  int ret;
  ret = write(cdev, msg, 4);
  // printf("write() ret: %d\n", ret);
}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
  if (type == INTERRUPT)
  {
    char msg[3];
    msg[0] = '3';
    msg[1] = value;
    int ret;
    ret = write(cdev, msg, 3);
    // printf("write() ret: %d\n", ret);
    return 0;
  }
  if (type == DMA)
  {
    char msg[3];
    msg[0] = '4';
    msg[1] = value;
    int ret;
    ret = write(cdev, msg, 3);
    // printf("write() ret: %d\n", ret);
    return 0;
  }
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
  if (size > 1024 * 1024)
  {
    return NULL;
  }
  size = 1024 * 1024;
  char *map_ptr = (char *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cdev, 0);
  map_ptr += 0xa8;
  return (void *)map_ptr;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
  munmap(addr - 0xa8, 1024 * 1024);
}
