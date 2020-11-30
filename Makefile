compile: main.c
	gcc -o main main.c
	strace ./main | grep eject

clean: remove


remove:
ifneq (,$(wildcard ./main))
	rm ./main
endif
