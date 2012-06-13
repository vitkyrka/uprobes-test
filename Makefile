CC = arm-linux-gnueabihf-gcc
CFLAGS += -O2 -Wall -marm -static

uprobes-test: main.o kprobes-test.o opcodes.o kprobes-test-arm.o probes.o
	$(CC) -o $@ $^ $(CFLAGS)

sigrec:

clean:
	@rm -f *.o uprobes-test sigrec
