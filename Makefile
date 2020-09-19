all: dummyplug

dummyplug: src/main.c
	gcc -o dummyplug src/main.c
