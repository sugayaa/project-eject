OBJ := main.o
CC := gcc -Wall
KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

compile: main.c
	$(MAKE) -C $(KDIR) M=$(PWD) main

clean: remove


remove:
ifneq (,$(wildcard ./main))
	rm ./main
endif
