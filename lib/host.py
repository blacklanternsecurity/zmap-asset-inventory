#!/usr/bin/env python3

# by TheTechromancer

import socket
import ipaddress


def str_to_network(s):
    '''
    takes either CIDR or range notation as string
    generates ip_network objects
    '''

    try:
        if '-' in s:
            if s.count('-') == 1:
                start, end = [p.strip() for p in s.split('-')[:2]]
                for i in ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)):
                    yield i
            else:
                raise ValueError()
        else:
            net = ipaddress.ip_network(s, strict=False)
            yield net

    except ValueError:
        print('[!] Cannot create host/network from "{}"'.format(str(s)))
        print('     Accepted formats are:')
        print('      192.168.0.0/24')
        print('      192.168.0.0-192.168.0.255')




class Host(dict):

    def __init__(self, ip, hostname=None, resolve=False):

        super().__init__()

        self['IP Address'] = str(ip)
        self['OS'] = 'Unknown'

        if not hostname:
            self['Hostname'] = ''
        else:
            self['Hostname'] = str(hostname)

        self.open_ports = set()

        if resolve:
            self.resolve()

        self.raw_wmiexec_output = ''


    def resolve(self):

        if not self['Hostname']:
            try:
                self['Hostname'] = socket.gethostbyaddr(self['IP Address'])[0]
            except socket.herror:
                self['Hostname'] = ''

        return self['Hostname']


    def merge(self, other):

        for key, value in other.items():
            if value.strip().lower() not in ['n/a', 'no', 'unknown', '']:
                self.update({key: value})


    @property
    def ip(self):

        try:
            return ipaddress.ip_address(self['IP Address'])
        except ValueError:
            return None


    @property
    def hostname(self):
        
        return self['Hostname']


    def __str__(self):

        return '{:<16}{}'.format(self['IP Address'], self['Hostname'])


    def __hash__(self):

        return hash(self['IP Address'])