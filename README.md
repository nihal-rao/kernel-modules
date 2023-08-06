# Kernel Modules
A collection of kernel modules written as part of assignments for the course CS614: Linux Kernel Programming at IIT Kanpur.

## Chardev
* A module to create character device and sysfs file. 
* The user process writes to the sysfs file and reads output from the chardev.
* Commands are as follows :
  * 0 - pid
  * 1 - static priority
  * 2 - command name
  * 3 - parent pid
  * 4 - number of voluntary context switches
  * 5 - number of threads in thread group
  * 6 - number of open files
  * 7 - pid of thread with max stack usage
* The module handles multiple processes simultaneously using the sysfs file and chardev.

## VMA manipulation
* A module to move VMA to a user specified location or the next available hole in the virtual address range with sufficient space.

## Cryptocard device driver
* A device driver for a PCI device called cryptocard, along with user space library to expose the functionalities of the device.
* CryptoCard is a PCI device that encrypts/decrypts the data by using a specified key pair a and b and returns the encryption/decryption result to the end-user.
* The device can perform encryption/decryption using MMIO or DMA.
* Both MMIO and DMA can be configured to raise an interrupt after the operation is finished by the device.

