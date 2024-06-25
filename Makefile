CFLAGS := -g -O0
MINGWCC := x86_64-w64-mingw32-gcc
MINGW++ := x86_64-w64-mingw32-g++-posix
WINDRES := x86_64-w64-mingw32-windres
WINECC := winegcc
CC := gcc
CXX := g++
WINEPREFIX ?= ~/.wine

MODULES = \
	keycont \
	providers \
	provider-algs \
	create-hash \
	create-req \
	https

all: $(MODULES)

.PHONY: keycont
keycont:
	$(MINGWCC) $@.c util.c $(CFLAGS) -lcrypt32 -o $@
	$(CC) $(CFLAGS) $@.c util.c -I /opt/cprocsp/include/cpcsp -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lrdrsup -o $@

providers:
	$(MINGWCC) $@.c $(CFLAGS) -o $@

provider-algs:
	$(MINGWCC) $@.c util.c $(CFLAGS) -o $@

create-rand:
	$(MINGWCC) $@.c util.c $(CFLAGS) -o $@

create-hash:
	$(MINGWCC) $@.c util.c $(CFLAGS) -o $@

.PHONY: create-req
create-req: create-req.c
	$(MINGWCC) $@.c $(CFLAGS) -lcrypt32 -o $@
	$(CC) $(CFLAGS) $@.c -I /opt/cprocsp/include/cpcsp -L/opt/cprocsp/lib/amd64 -lcapi10 -lcapi20 -lrdrsup -o $@

https:
	$(MINGWCC) $(CFLAGS) $@.c wineutil.c -I/opt/cprocsp/include/cpcsp -I/home/ten0s/Avest_AvSDK/AvCSPSDK/examples/CAPI/CAPI1 -lcrypt32 -lcryptui -lws2_32 -o $@

clean:
	rm -f *.exe *.so
