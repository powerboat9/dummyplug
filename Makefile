all: dummyplug build/zoompre.so

dummyplug: src/main.c
	gcc -o dummyplug src/main.c

build/preload.o: src/preload.c
	gcc -c -fPIC -o $@ $^

build/zoompre.so: build/preload.o
	gcc -ldl -pthread -shared -o $@ $^

clean:
	rm -- build/* || true
