import os
import sys
import json

def gdb_printer_decorator(fn):
    gdb.pretty_printers.append(fn)
    return fn

class ldap_valuelist_Printer(object):
    def __init__(self, val):
        self.val = val

    def singleton(self):
        return self.val['head'] == self.val['tail']

    def display_hint(self):
        if self.singleton():
            return "string"
        else:
            return "array"

    def to_string(self):
        head = self.val['head']
        if not head:
            return "(empty value list)"
        if self.singleton():
            return head['value'].string()
        return None

    def children(self):
        if self.singleton():
            return []
        i = 0
        l = []
        head = self.val['head']
        while head:
            l.append((str(i), '"%s"' % head['value'].string()))
            if head['link']['next']:
                head = head['link']['next'].dereference()
            else:
                head = None
            i += 1
        return l

# register pretty printers
@gdb_printer_decorator
def dns_rbt_printer(val):
    if str(val.type) == 'ldap_valuelist_t':
        return ldap_valuelist_Printer(val)
    return None
