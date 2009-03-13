.PHONY: all clean

LIBMAJOR = 1
LIBMINOR = 0

LIBNAME = libdnsldap.so.$(LIBMAJOR).$(LIBMINOR).0
LIBSONAME = libdnsldap.so.$(LIBMAJOR)
OBJS  = ldap_driver.o semaphore.o ldap_convert.o ldap_helper.o log.o rdlist.o
OBJS += settings.o str.o zone_manager.o

CFLAGS := -Wall -Wextra -pedantic -std=c99 -g -fPIC $(CFLAGS)


all: $(LIBNAME)

clean:
	rm -f $(LIBNAME) *.o

$(LIBNAME): $(OBJS)
	$(CC) -ldns -lldap -shared -Wl,-soname,$(LIBSONAME) $+ -o $@
