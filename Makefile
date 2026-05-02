CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g

SHIM_SRC = shim/win32_shim.c
SHIM_HDR = shim/win32_shim.h

.PHONY: all clean shim_demo

all: shim_demo

shim_demo: $(SHIM_SRC) shim/shim_demo.c $(SHIM_HDR)
	$(CC) $(CFLAGS) -o shim_demo $(SHIM_SRC) shim/shim_demo.c

clean:
	rm -f shim_demo
