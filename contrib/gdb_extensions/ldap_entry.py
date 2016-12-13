import os
import sys
import json

def gdb_printer_decorator(fn):
    gdb.pretty_printers.append(fn)
    return fn

class ldap_entry_Printer(object):
    def __init__(self, val):
        self.val = val

    def display_hint(self):
        return 'array'

    def to_string(self):
        out = "entry DN: %s" % self.val['dn'].string()
        return out

    def children(self):
        i = 0
        l = []
        head = self.val['attrs']['head'].dereference()
        while head:
            l.append((str(i), head))
            if head['link']['next']:
                head = head['link']['next'].dereference()
            else:
                head = None
            i += 1
        return l

class TestPrinter(object):
    def __init__(self, val):
        self.val = val

    def to_string(self):
        return str(self.val.type)

# register pretty printers
@gdb_printer_decorator
def ldap_entry_printer(val):
    if str(val.type) == 'ldap_entry_t' or str(val.type) == 'const ldap_entry_t':
        return ldap_entry_Printer(val)
    return None
