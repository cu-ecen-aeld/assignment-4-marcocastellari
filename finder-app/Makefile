# Native compiler for your host machine (x86_64)
CC=gcc
# Prefix for cross-compiler toolchain
CROSS_COMPILE=aarch64-none-linux-gnu

# Run with: make writer
writer: writer.c
	$(CC) writer.c -o writer

# Run with: make writer-arm
writer-arm: writer.c
	$(CROSS_COMPILE)-$(CC) writer.c -o writer-arm

# Run with: make clean
clean:
	rm -f writer writer-cc *.o *.elf *.map