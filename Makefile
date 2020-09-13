all: dummyplug

dummyplug: main.c
	gcc -o dummyplug main.c
