CC := gcc

.PHONY: run

run: main
	./main

main: main.o ev_kqueue.o

.PHONY: clean
clean:
	$(RM) *.o main
