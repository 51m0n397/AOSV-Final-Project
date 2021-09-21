# AOSV Final Project
_A.Y. 2020/2021_

## Author(s)

The author of this project is Simone Bartolini (1752197)

## Instructions

### Tree

- `doc/` contains the final report and the documentation
- `src/` contains the source code

### Compilation and execution

- In order to compile the source code you need gcc and the kernel headers for linux version 5.11.2;
- use the makefile in `src/kernel/` to compile the kernel module;
- use the makefile in `src/user/` to compile the test program;
- the kernel module can be loaded with the command `sudo insmod ums_module.ko`;