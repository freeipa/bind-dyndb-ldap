#!/usr/bin/env python3
#
# Copyright (C) 2014  bind-dyndb-ldap authors; see COPYING for license
#

import logging
import os
import re
import json
import xmlrpc.client

log = logging.getLogger('trac')

class Trac():
    def __init__(self, protocol, url, username, passwd):
        self.baseurl = '%s://%s' % (protocol, url)
        loginurl = '%s://%s:%s@%s/login/xmlrpc' % (protocol, username, passwd, url)
        self.api = xmlrpc.client.ServerProxy(loginurl)
    
    def match_ticket_url(self, line):
        return re.match("^ +%s/ticket/([0-9]+) *$" % self.baseurl, line)

    def get_ticket_attrs(self, ticketid):
        ticket = self.api.ticket.get(ticketid)
        assert str(ticket[0]) == str(ticketid)
        return ticket[3]

def trac_autoconf():
    """
    Configuration file format is:
    {"protocol": "https",
     "url": "fedorahosted.org/bind-dyndb-ldap",
     "username": "FedoraUserName",
     "passwd": "FedoraPassword"}
    """
    config = json.load(open(os.path.expanduser('~/.trac')))
    return Trac(**config)

if __name__ == "__main__":
    t = trac_autoconf()
    logging.basicConfig(level=logging.DEBUG)
    log.debug(t.api)
