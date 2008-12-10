.PHONY: all clean

LIBMAJOR = 1
LIBMINOR = 0

LIBNAME = libdnsldap.so.$(LIBMAJOR).$(LIBMINOR).0
LIBSONAME = libdnsldap.so.$(LIBMAJOR)
LIBSOURCES = ldap_driver.c semaphore.o log.o

ALL_CFLAGS = -Wall -Wextra -pedantic -std=c99 -g -fPIC $(CFLAGS)


all: $(LIBNAME) semaphore.o

clean:
	rm -f $(LIBNAME) *.o

$(LIBNAME): $(LIBSOURCES)
	$(CC) $(ALL_CFLAGS) -ldns -lldap -shared -Wl,-soname,$(LIBSONAME) $+ -o $@

semaphore.o: semaphore.c
	$(CC) $(ALL_CFLAGS) -c $+ -o $@

log.o: log.c
	$(CC) $(ALL_CFLAGS) -c $+ -o $@
