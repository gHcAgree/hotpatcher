.PHONY: all clean 

all:
	gcc -g -o hotpatcher hotpatcher.c dl.c utils.c mcount.S -I./ -lbfd -ldl -pg
	gcc -g -fPIC -pg -c sample_functions.c
	gcc -shared -o sample_lib.so sample_functions.o

clean:
	rm -f hotpatcher sample_lib.so sample_functions.o
	-rm -f gmon.out
