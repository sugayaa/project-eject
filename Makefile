OBJ := main.o
CC := gcc -Wall -I /usr/include/
KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m += main.o

compile: main.c
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean: remove


remove:
ifneq (,$(wildcard ./main))
	rm ./main
endif
