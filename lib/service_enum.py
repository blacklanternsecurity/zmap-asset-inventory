#!/usr/bin/env python3

# by TheTechromancer

import os
import json
import configparser
from time import sleep
import subprocess as sp
from shutil import which
from pathlib import Path
import concurrent.futures
from datetime import datetime


class ServiceEnumException(Exception):
    pass

class LogonFailureException(Exception):
    pass


def parse_service_config(config_file):

    try:

        config = configparser.ConfigParser()
        config.read(config_file)

        if not config:
            raise KeyError('Error parsing config file')

        # make sure we have credentials
        if not config['CREDENTIALS']['username'] or not (config['CREDENTIALS']['password'] \
            or config['CREDENTIALS']['hashes']):
            try:
                ticket_var = Path(os.environ['KRB5CCNAME'])
                ticket = True
            except KeyError:
                print('[!] Username or password missing and no KRB5CCNAME variable found.')
                return

        return config

    except (KeyError, TypeError) as e:
        print('[!] Problem with config file at {}'.format(str(config_file)))
        print('\t' + str(e))



class wmiexec:

    def __init__(self, target, config):

        self.target   = target['IP Address']
        self.username = config['CREDENTIALS']['username']
        self.password = config['CREDENTIALS']['password']
        self.domain   = config['CREDENTIALS']['domain']
        self.hashes   = config['CREDENTIALS']['hashes']
        self.services = config['SERVICES']

        self.wmi_auth = ''

        self.raw_output = ''

        self.ticket = False
        if not self.username or not (self.password or self.hashes):
            try:
                os.environ['KRB5CCNAME']
                self.wmi_auth = ['-k', '-no-pass', self.target]
                if target['Hostname']:
                    self.target = target['Hostname']
                else:
                    raise ValueError('Ticket authentication needs valid hostname, none found for {}, skipping'.format(str(target['IP Address'])))
            except KeyError:
                raise ValueError('Kerberos ticket not found, please export "KRB5CCNAME" variable')
        elif self.password:
            self.wmi_auth = ['{}/{}:{}@{}'.format(self.domain, self.username, self.password, self.target)]
        elif self.hashes:
            self.wmi_auth = ['-hashes', self.hashes, '{}/{}@{}'.format(self.domain, self.username, self.target)]
        else:
            raise ValueError('Specified authentication method not valid.  Please check services.config.')


    def get_services(self):
        '''
        enumerates requested services
        returns tuple (os_name: { service_fname: True|False ... } )
        returns None if no unreachable
        returns empty string if no results
        '''

        service_keywords = set()
        for service_name in self.services.values():
            [service_keywords.add(word) for word in service_name.split()]

        canary = '!@#'
        canary_cmd = 'echo {}'.format(canary)

        win_commands = ['(', canary_cmd, '&', \
        '''reg query "hklm\\software\\microsoft\\windows nt\\currentversion" /v productname''', '&',
        canary_cmd, '&', '''sc query | findstr /i "{}"'''.format(' '.join(service_keywords)), ')']

        stdout,stderr = self.run_wmiexec(' '.join(win_commands))

        if 'STATUS_LOGON_FAILURE' in stdout:
            raise LogonFailureException(stdout + stderr)
        elif not canary in stdout:
            raise ServiceEnumException(stdout + stderr)

        else:
            try:
                os_str, svc_str = [[line.strip() for line in chunk.split('\r\n') if line.strip()] for chunk in stdout.split(canary)[1:3]]
            except ValueError:
                raise ServiceEnumException(stdout + stderr)
            '''
            print('=' * 20)
            print('\n'.join(os_str))
            print('=' * 20)
            print('\n'.join(svc_str))
            print('=' * 20)
            '''

        os_name = ' '.join(os_str[-1].split()[2:])

        services_detected = dict()
        for (fname, sname) in self.services.items():
            sname = sname.upper()

            services_detected[fname] = 'No'

            for s in svc_str:
                svc_name = ':'.join(s.split(':')[1:]).strip().upper()
                if sname in svc_name:
                    services_detected[fname] = 'Yes'
                    break

        # print(os_name, services_detected)
        return (os_name, services_detected)

        # echo !@# && reg query "hklm\software\microsoft\windows nt\currentversion" /v productname && echo !@# && sc query | findstr /i data


    def run_wmiexec(self, command, timeout=10):

        if which('wmiexec'):
            wmiexec_script = 'wmiexec'
        elif which('wmiexec.py'):
            wmiexec_script = 'wmiexec.py'
        else:
            print('[+] Unable to find wmiexec in $PATH')
            return

        wmiexec_command = [wmiexec_script] + self.wmi_auth + [command]

        # print(' >> ' + ' '.join(wmiexec_command))
        try:
            wmiexec_process = sp.run(wmiexec_command, stdout=sp.PIPE, stderr=sp.PIPE, timeout=timeout)
            self.raw_stdout = wmiexec_process.stdout.decode()
            self.raw_stderr = wmiexec_process.stderr.decode()
            return (self.raw_stdout, self.raw_stderr)
        except sp.TimeoutExpired:
            raise ServiceEnumException('wmiexec timed out:\n{}'.format(' '.join(wmiexec_command)))


    @staticmethod
    def report(config, hosts):

        os_stats = dict()
        service_stats = dict()

        service_stats_workstations = dict()
        service_stats_servers = dict()

        hosts_total = 0
        workstations_total = 0
        servers_total = 0

        service_names = list(config['SERVICES'].items())

        for host in hosts:
            try:
                os = host['OS']
                if os.upper() != 'UNKNOWN':
                    try:
                        os_stats[os] += 1
                    except KeyError:
                        os_stats[os] = 1

                for fname,sname in service_names:
                    host_has_service = host[fname]

                    if host_has_service == 'Yes':
                        try:
                            service_stats[fname] += 1
                        except KeyError:
                            service_stats[fname] = 1

                        if 'Server' in os:
                            try:
                                service_stats_servers[fname] += 1
                            except KeyError:
                                service_stats_servers[fname] = 1
                        else:
                            try:
                                service_stats_workstations[fname] += 1
                            except KeyError:
                                service_stats_workstations[fname] = 1

                hosts_total += 1
                if 'Server' in os:
                    servers_total += 1
                else:
                    workstations_total += 1

            except KeyError:
                continue

        report = []

        report.append('SERVICES:')

        service_stats = list(service_stats.items())
        service_stats.sort(key=lambda x: x[1], reverse=True)

        service_stats_servers = list(service_stats_servers.items())
        service_stats_servers.sort(key=lambda x: x[1], reverse=True)

        service_stats_workstations = list(service_stats_workstations.items())
        service_stats_workstations.sort(key=lambda x: x[1], reverse=True)

        report.append('\tGlobal:')
        for service, count in service_stats:
            report.append('\t\t{}: {:,}/{:,} ({:.2f}%)'.format(service, count, hosts_total, count/hosts_total*100))
        for service_name in service_names:
            if service_name[0] not in [s[0] for s in service_stats]:
                report.append('\t\t{}: 0/0 (0.0%)'.format(service_name[0]))

        report.append('\tWorkstations:')
        for service, count in service_stats_workstations:
            report.append('\t\t{}: {:,}/{:,} ({:.2f}%)'.format(service, count, workstations_total, count/workstations_total*100))
        for service_name in service_names:
            if service_name[0] not in [s[0] for s in service_stats_workstations]:
                report.append('\t\t{}: 0/0 (0.0%)'.format(service_name[0]))

        report.append('\tServers:')
        for service, count in service_stats_servers:
            report.append('\t\t{}: {:,}/{:,} ({:.2f}%)'.format(service, count, servers_total, count/servers_total*100))
        for service_name in service_names:
            if service_name[0] not in [s[0] for s in service_stats_servers]:
                report.append('\t\t{}: 0/0 (0.0%)'.format(service_name[0]))

        report.append('\nOPERATING SYSTEMS:')
        os_stats = list(os_stats.items())
        os_stats.sort(key=lambda x: x[1], reverse=True)
        for os, count in os_stats:
            report.append('\t{}: {:,}/{:,} ({:.2f}%)'.format(os, count, hosts_total, count/hosts_total*100))

        return '\n'.join(report)



"""
# some random tests

start_time = datetime.now()

c = parse_service_config('services.config')
w = wmiexec('10.0.0.119', c)
print(w.get_services())

'''
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(wmiexec, '1.2.3.4', c, 'Admin', 'asdf') for c in commands]

    for future in concurrent.futures.as_completed(futures):
        print(future.result())
'''

end_time = datetime.now()

print('Time elapsed: {date}'.format( date=(end_time-start_time)))

'''
start_time = datetime.now()
for c in commands:
    print(wmiexec('10.0.0.119', c, 'Admin', 'asdf'))

end_time = datetime.now()
print('Time elapsed: {date}'.format( date=(end_time-start_time)))
'''
"""