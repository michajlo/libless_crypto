
all: test

test: clean
	gcc -Wall test.c aes.c -o test_suite
	./test_suite

clean:
	rm -rf test_suite *.o
