#!/usr/bin/env python3

import io
import os
import csv
import sys
import socket
import pickle
import argparse
import tempfile
import ipaddress
import threading
from time import sleep
import subprocess as sp
from pathlib import Path
from datetime import datetime
import xml.etree.cElementTree as xml # for parsing Nmap output


class Zmap:

    def __init__(self, targets, bandwidth, work_dir, blacklist=None):

        self.targets                    = targets
        self.hosts                      = dict()
        self.eternal_blue_count         = 0
        self.scanned_eternal_blue       = False
        self.ports_scanned              = set()
        self.host_discovery_finished    = False


        self.online_hosts_file          = str(work_dir / 'zmap_online_hosts.txt')

        self.update_config(bandwidth, work_dir, blacklist)


    def start(self):

        #if not self.primary_zmap_started and not host_discovery_finished:
        self.primary_zmap_started = True

        zmap_command = ['zmap', '--blacklist-file={}'.format(self.blacklist), \
            '--bandwidth={}'.format(self.bandwidth), \
            '--probe-module=icmp_echoscan'] + self.targets

        print('\n[+] Running zmap:\n\t> {}\n'.format(' '.join(zmap_command)))

        try:
            self.primary_zmap_process = sp.Popen(zmap_command, stdout=sp.PIPE)
        except sp.CalledProcessError as e:
            sys.stderr.write('[!] Error launching zmap: {}\n'.format(str(e)))
            sys.exit(1)


    def stop(self):

        try:
            self.primary_zmap_process.terminate()
            self.secondary_zmap_process.terminate()
        except AttributeError:
            pass
        finally:
            self.primary_zmap_started = False
            self.secondary_zmap_started = False
            self.primary_zmap_process = None
            self.secondary_zmap_process = None


    def hosts_sorted(self):

        hosts_sorted = list(self.hosts.values())
        hosts_sorted.sort(key=lambda x: ipaddress.IPv4Address(x['IP Address']))
        return hosts_sorted


    def check_eternal_blue(self):

        print('\n[+] Scanning for EternalBlue')

        for ip in Nmap(self.scan_online_hosts(port=445), work_dir=self.work_dir):
            self.eternal_blue_count += 1
            try:
                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
            except KeyError:
                self.hosts[ip] = Host(ip)
                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'

        self.scanned_eternal_blue = True


    def report(self):

        print('\n\n[+] RESULTS:')
        print('=' * 50)
        print('[+] Total Online Hosts: {:,}'.format(len(self.hosts)))
        print('[+] Summary of Subnets:')
        for subnet in self._count_subnets():
            print('\t{:<15}{:<10}'.format(subnet[0], ' ({:,})'.format(subnet[1])))

        if self.eternal_blue_count > 0:
            print('')
            print('[+] Vulnerable to EternalBlue: {:,}\n'.format(self.eternal_blue_count))
            for host in self.hosts.values():
                if host['Vulnerable to EternalBlue'] == 'Yes':
                    print('\t{}'.format(str(host)))
        elif self.scanned_eternal_blue:
            print('[+] No systems found vulnerable to EternalBlue')

        print('')


    def scan_online_hosts(self, port):

        port = int(port)
        zmap_out_file = self.work_dir / 'zmap_port_{}.txt'.format(port)

        if not self.secondary_zmap_started and not port in self.ports_scanned:

            self.ports_scanned.add(port)

            print('[+] Scanning {:,} hosts on port {}'.format(len(self.hosts), port))

            self.secondary_zmap_started = True

            # run the main scan if it hasn't already completed
            for host in self:
                pass

            zmap_command = ['zmap', '--whitelist-file={}'.format(self.online_hosts_file), \
                '--bandwidth={}'.format(self.bandwidth), \
                '--target-port={}'.format(port)]

            print('\n[+] Running zmap:\n\t> {}\n'.format(' '.join(zmap_command)))

            try:
                self.secondary_zmap_process = sp.Popen(zmap_command, stdout=sp.PIPE)
                sleep(2)

                with open(zmap_out_file, 'w') as f:
                    for line in io.TextIOWrapper(self.secondary_zmap_process.stdout, encoding='utf-8'):
                        ip = line.strip()
                        print('[+] {:<23}{:<10}'.format('{}:{}'.format(self.hosts[ip]['IP Address'], port), self.hosts[ip]['Hostname']))
                        f.write(ip + '\n')
                        self.hosts[ip].open_ports.add(port)

            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching zmap: {}\n'.format(str(e)))
                sys.exit(1)

            self.secondary_zmap_started = False
            self.secondary_zmap_process = None

        return zmap_out_file


    def update_config(self, bandwidth, work_dir, blacklist=None):

        self.bandwidth              = str(bandwidth).upper()
        self.primary_zmap_process   = None
        self.primary_zmap_started   = False
        self.secondary_zmap_process = None
        self.secondary_zmap_started = False
        self.work_dir               = work_dir

        # validate bandwidth arg
        if not any([self.bandwidth.endswith(s) for s in ['K', 'M', 'G']]):
            raise ValueError('Invalid bandwidth: {}'.format(self.bandwidth))

        # validate blacklist arg
        if blacklist is None:
            blacklist = work_dir / '.zmap_blacklist_tmp'
            blacklist.touch(mode=0o644, exist_ok=True)
            self.blacklist = str(blacklist)
        else:
            self.blacklist = Path(blacklist)
            if not self.blacklist.is_file():
                raise ValueError('Cannot process blacklist file: {}'.format(str(self.blacklist)))
            else:
                self.blacklist = str(self.blacklist.resolve())


    def _count_subnets(self):

        subnets = dict()

        for ip in self.hosts:
            subnet = '.'.join(ip.split('.')[:2]) + '.X.X'
            try:
                subnets[subnet] += 1
            except KeyError:
                subnets[subnet] = 1

        subnets = list(subnets.items())
        subnets.sort(key=lambda x: x[1], reverse=True)
        return subnets


    def __iter__(self):

        if self.host_discovery_finished:

            for host in self.hosts.values():
                yield host

        else:

            self.primary_zmap_started = True

            with open(self.online_hosts_file, 'w') as f:

                self.start()
                sleep(1)
                for line in io.TextIOWrapper(self.primary_zmap_process.stdout, encoding='utf-8'):
                    ip = line.strip()
                    host = Host(ip, resolve=True)
                    print('[+] {:<17}{:<10} '.format(host['IP Address'], host['Hostname']))
                    self.hosts[ip] = host
                    f.write(host['IP Address'] + '\n')
                    yield host

            self.primary_zmap_started = False
            self.host_discovery_finished = True




class Nmap:

    def __init__(self, targets_file, work_dir):

        self.process            = None
        self.output_file    = str(work_dir / 'nmap_output')
        self.finished           = False
        self.targets_file       = str(targets_file)

        self.hosts = dict()


    def __iter__(self):
        '''
        Yields IPs of hosts vulnerable to EternalBlue
        '''

        if not self.finished:

            command = ['nmap', '-p445', '-T5', '-n', '-Pn', '-v', '-sV', \
                '--script=smb-vuln-ms17-010', '-oA', self.output_file, \
                '-iL', self.targets_file]

            print('\n[+] Running nmap:\n\t> {}'.format(' '.join(command)))

            try:
                self.process = sp.run(command, check=True)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching nmap: {}\n'.format(str(e)))
                sys.exit(1)

            print('\n[+] Finished Nmap scan')

            # parse xml
            # print('[+] Parsing Nmap results')

            tree = xml.parse(self.output_file + '.xml')

            for host in tree.findall('host'):
                pass

                ip = None
                for address in host.findall('address'):
                    if address.attrib['addrtype'] == 'ipv4':
                        ip = address.attrib['addr']
                        break

                if ip is None:
                    continue

                else:
                    self.hosts[ip] = Host(ip)
                    for hostscript in host.findall('hostscript'):
                        for script in hostscript.findall('script'):
                            if script.attrib['id'] == 'smb-vuln-ms17-010' and 'VULNERABLE' in script.attrib['output']:
                                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
                                yield ip

            self.finished = True

        else:
            for host in self.hosts.values():
                if host['Vulnerable to EternalBlue'] == 'Yes':
                    yield host['IP Address']

        print('[+] Saved Nmap results to {}.*'.format(self.output_file))




class Host(dict):

    def __init__(self, ip, resolve=False):

        super().__init__()
        self['IP Address'] = ip
        self['Hostname'] = ''
        self['Vulnerable to EternalBlue'] = 'No'
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


    def __str__(self):

        return '{}{}'.format(self['IP Address'], (' ({})'.format(self['Hostname']) if self['Hostname'] else ''))



if __name__ == '__main__':

    if os.geteuid() != 0:
        sys.stderr.write('[!] Must be root\n')
        sys.exit(1)

    default_bandwidth = '500K'
    default_work_dir = Path.home() / '.asset_inventory'
    default_csv_file = default_work_dir / 'asset_inventory.csv'

    parser = argparse.ArgumentParser("Scan private IP ranges, output to CSV")
    parser.add_argument('-t', '--targets', nargs='+', default=['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'], help='target network(s) to scan', metavar='STR')
    parser.add_argument('-B', '--bandwidth', default=default_bandwidth,     help='max egress bandwidth (default {})'.format(default_bandwidth), metavar='STR')
    parser.add_argument('--blacklist',      default=None,                   help='a file containing hosts to exclude from scanning', metavar='FILE')
    parser.add_argument('-w', '--csv-file',                                 help='output CSV file', metavar='CSV_FILE')
    parser.add_argument('-f', '--start-fresh',        action='store_true',  help='don\'t load results from previous scans')
    parser.add_argument('-p', '--ports', nargs='+', type=int,               help='port-scan online hosts')
    parser.add_argument('-e', '--check-eternal-blue', action='store_true',  help='scan for EternalBlue')
    parser.add_argument('--work-dir',       type=Path,                      help='custom working directory')

    try:

        options = parser.parse_args()
        options.targets = list(set(options.targets))
        options.targets.sort()

        if options.work_dir is None:
            # unique identifier based on scan targets
            scan_uid = '_'.join([t.replace('/', '-') for t in options.targets])
            options.work_dir = default_work_dir / scan_uid

        # resolve symlinks
        options.work_dir = options.work_dir.resolve()

        # default CSV output
        if options.csv_file is None:
            options.csv_file = options.work_dir / 'asset_inventory.csv'

        # if starting fresh rename working directory to ".bak"
        if options.start_fresh:
            backup_work_dir = Path(str(options.work_dir) + '_{date:%Y-%m-%d_%H:%M:%S}.bak'.format( date=datetime.now() ))
            try:
                options.work_dir.rename(backup_work_dir)
            except FileNotFoundError:
                pass

        # create working directory if it doesn't exist
        options.work_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

        # try to load "Zmap" object from pickled state
        saved_state = str(options.work_dir / '.state')
        try:

            with open(saved_state, 'rb') as f:
                z = pickle.load(f)
                print('[+] Loaded saved state from {}'.format(saved_state))
                z.update_config(options.bandwidth, work_dir=options.work_dir, blacklist=options.blacklist)

        except (FileNotFoundError, EOFError):
            print('[+] No state found at {}, starting fresh'.format(saved_state))
            z = Zmap(options.targets, options.bandwidth, work_dir=options.work_dir, blacklist=options.blacklist)

        # write CSV file
        with open(options.csv_file, 'w', newline='') as f:
            csvfile = csv.DictWriter(f, fieldnames=['IP Address', 'Hostname', 'Vulnerable to EternalBlue'])
            csvfile.writeheader()

            # make sure initial discovery scan has completed
            for host in z:
                pass

            for host in z.hosts_sorted():
                csvfile.writerow(host)

        # check for EternalBlue
        if options.check_eternal_blue:
            z.check_eternal_blue()

        # scan additional ports, if requested
        # only alive hosts are scanned
        if options.ports is not None:
            for port in options.ports:
                z.scan_online_hosts(port)

        # print summary
        z.report()

        print('[+] CSV file written to {}'.format(options.csv_file))


    except (argparse.ArgumentError, ValueError) as e:
        sys.stderr.write('\n[!] {}\n'.format(str(e)))
        sys.exit(2)

    except KeyboardInterrupt:
        sys.stderr.write('\n[!] Interrupted\n')
        sys.exit(1)

    finally:
        try:
            z.stop()

            # pickle Zmap object to save state
            with open(saved_state, 'wb') as f:
                pickle.dump(z, f)
        except:
            pass