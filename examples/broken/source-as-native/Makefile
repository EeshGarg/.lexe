# Nothing to build: the whole point is that the SOURCE is declared as the
# entrypoint. `lexe build` copies payload/ as it stands.
all:
	mkdir -p payload/src
	cp src/main.c payload/src/main.c
clean:
	rm -rf payload
.PHONY: all clean
