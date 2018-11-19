CC := gcc

.PHONY: run

run: main
	./main

main: main.o

.PHONY: clean
clean:
	$(RM) *.o main
