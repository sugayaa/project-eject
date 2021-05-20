KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m += main.o

compile: main.c
	make -C $(KDIR) M=$(PWD)

clean: remove


remove:
ifneq (,$(wildcard ./main))
	rm ./main
endif
