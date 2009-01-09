.PHONY: all clean

LIBMAJOR = 1
LIBMINOR = 0

LIBNAME = libdnsldap.so.$(LIBMAJOR).$(LIBMINOR).0
LIBSONAME = libdnsldap.so.$(LIBMAJOR)
OBJS = ldap_driver.o semaphore.o log.o str.o

CFLAGS := -Wall -Wextra -pedantic -std=c99 -g -fPIC $(CFLAGS)


all: $(LIBNAME)

clean:
	rm -f $(LIBNAME) *.o

$(LIBNAME): $(OBJS)
	$(CC) -ldns -lldap -shared -Wl,-soname,$(LIBSONAME) $+ -o $@
