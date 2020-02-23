Erebus.bin: Erebus.c
	gcc -fPIC -pie -fomit-frame-pointer -fstack-protector -Wl,-z,relro,-z,now \
		-Wl,-z,separate-code -o Erebus.bin Erebus.c

victim.bin: victim.c
	gcc -o victim.bin victim.c

hostile.so: hostile.c
	gcc -fPIC  -c hostile.c -nostdlib -fomit-frame-pointer
	ld -shared -o hostile.so hostile.o

build: Erebus.bin victim.bin hostile.so

run_victim: build
	./victim.bin

run_infector: build
	sudo ./Erebus.bin `pidof victim.bin` puts hostile.so

clean:
	rm -rf *.o *.bin *.so
