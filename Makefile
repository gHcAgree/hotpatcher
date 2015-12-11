.PHONY: all clean new

CFLAGS = -g -ffunction-sections -fdata-sections -pg -mfentry -fPIC
LDFLAGS = -lbfd -ldl -pg -mfentry

all:
	gcc $(CFLAGS) -c sample_functions.c 
	gcc $(CFLAGS) -c mcount.S
	gcc $(CFLAGS) -c utils.c
	gcc $(CFLAGS) -c dl.c
	gcc $(CFLAGS) -c hotpatcher.c
	gcc -o hotpatcher hotpatcher.o dl.o utils.o mcount.o sample_functions.c $(LDFLAGS)

new:
	gcc $(CFLAGS) -c sample_functions.c -o sample_functions_new.o

patch:
	gcc -shared hpatch2.o -o hpatch.so 

clean:
	rm -f hotpatcher *.o *.so
	-rm -f gmon.out
