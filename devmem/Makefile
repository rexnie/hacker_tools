all: devmem2 devmem2-64

devmem2: devmem2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ devmem2.c

devmem2-64: devmem2-64.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ devmem2-64.c

install:
	mkdir -p $(DESTDIR)/usr/bin
	install devmem2 $(DESTDIR)/usr/bin
	install devmem2-64 $(DESTDIR)/usr/bin

clean:
	rm -f devmem2
	rm -f devmem2-64
