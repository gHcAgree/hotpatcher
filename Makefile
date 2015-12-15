.PHONY: orig clean new patch right

CFLAGS = -g -ffunction-sections -fdata-sections -pg -mfentry
NCFLAGS = $(CFLAGS) -fPIC
LDFLAGS = -lbfd -ldl -pg -mfentry

orig:
	gcc $(CFLAGS) -c sample_functions.c 
	gcc $(CFLAGS) -c mcount.S
	gcc $(CFLAGS) -c utils.c
	gcc $(CFLAGS) -c dl.c
	gcc $(CFLAGS) -c hotpatcher.c
	gcc -o hotpatcher hotpatcher.o dl.o utils.o mcount.o sample_functions.o $(LDFLAGS)

new:
	patch < function_patch.patch
	gcc $(NCFLAGS) -c sample_functions.c -o sample_functions_new.o
	gcc $(NCFLAGS) -c mcount.S
	gcc $(NCFLAGS) -c utils.c
	gcc $(NCFLAGS) -c dl.c
	gcc $(NCFLAGS) -c hotpatcher.c
	gcc -o hotpatcher_new hotpatcher.o dl.o utils.o mcount.o sample_functions_new.o $(LDFLAGS)
	git checkout sample_functions.c
	gcc $(NCFLAGS) -c sample_functions.c -o sample_functions_pre.o

patch:
	./gelf/create-diff-object sample_functions_pre.o sample_functions_new.o hotpatcher_new hpatch.o
	gcc -shared hpatch.o utils.o -o hpatch.so -lc

right:
	gcc -shared sample_functions_new.o utils.o -o sample_functions_new.so

clean:
	rm -f hotpatcher hotpatcher_new *.o *.so
	-rm -f gmon.out
