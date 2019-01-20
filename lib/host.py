#!/usr/bin/env python3

import socket
from lib.service_enum import *

class Host(dict):

    def __init__(self, ip, hostname=None, resolve=False):

        super().__init__()

        self['IP Address'] = str(ip)
        self['OS'] = 'Unknown'

        if not hostname:
            self['Hostname'] = ''
        else:
            self['Hostname'] = str(hostname)

        self['Vulnerable to EternalBlue'] = 'N/A'
        self.open_ports = set()

        if resolve:
            self.resolve()


    def resolve(self):

        if not self['Hostname']:
            try:
                self['Hostname'] = socket.gethostbyaddr(self['IP Address'])[0]
            except socket.herror:
                self['Hostname'] = ''

        return self['Hostname']


    def merge(self, other):

        hostname = self['Hostname']
        self.update(other)

        if hostname and not self['Hostname']:
            self['Hostname'] = hostname


    def get_services(self, config):

        w = wmiexec(self['IP Address'], config)
        os_name, services_detected = w.get_services()

        if os_name:
            self['OS'] = os_name

        for fname,sname in services_detected.items():
            self[fname] = sname


    def __str__(self):

        return '{:<16}{}'.format(self['IP Address'], self['Hostname'])


    def __hash__(self):

        return hash(self['IP Address'])