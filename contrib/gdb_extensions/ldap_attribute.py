import os
import sys
import json

def gdb_printer_decorator(fn):
    gdb.pretty_printers.append(fn)
    return fn

class ldap_attribute_Printer(object):
    def __init__(self, val):
        self.val = val
        self.values_pp = gdb.default_visualizer(val['values'])
        self.l = self._enumerate_children()
    
    def singleton(self):
        return self.values_pp and len(self.l) <= 1

    def display_hint(self):
        if self.singleton():
            return "string"
        else:
            return "array"

    def _enumerate_children(self):
        values = self.val['values']
        # pretty printer for ldap_valuelist returns array so [('0', values)]
        # results in list inside list which is not pretty
        # -> remove inner list
        if not self.values_pp:
            # prettyprinter for ldap_valuelist is not available
            return False

        l = []
        for v in self.values_pp.children():
            l.append(v)
        return l

    def to_string(self):
        out = "attribute: %s" % self.val['name'].string()
        if self.singleton():
            out += ' = { %s }' % self.values_pp.to_string()

        return out

    def children(self):
        if self.singleton():
            return []
        l = self._enumerate_children()
        if not l: # pretty printer is not available - cannot enumerate children
            return [('0', self.val['values'])]
        else:
            return l

# register pretty printers
@gdb_printer_decorator
def dns_rbt_printer(val):
    if str(val.type) == 'ldap_attribute_t':
        return ldap_attribute_Printer(val)
    return None
