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
            '--probe-module=icmp_echoscan'] + [str(t) for t in self.targets]

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
        hosts_sorted.sort(key=lambda x: ipaddress.ip_address(x['IP Address']))
        return hosts_sorted


    def check_eternal_blue(self):

        print('\n[+] Scanning for EternalBlue')

        for ip in Nmap(self.scan_online_hosts(port=445)[0], work_dir=self.work_dir):
            self.eternal_blue_count += 1
            try:
                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
            except KeyError:
                self.hosts[ip] = Host(ip)
                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'

        self.scanned_eternal_blue = True


    def report(self, netmask=24):

        print('\n\n[+] RESULTS:')
        print('=' * 50)
        print('[+] Total Online Hosts: {:,}'.format(len(self.hosts)))
        print('[+] Summary of Subnets:')
        summarized_hosts = list(self.summarize_online_hosts(netmask=netmask).items())
        summarized_hosts.sort(key=lambda x: x[1], reverse=True)
        for subnet in summarized_hosts:
            print('\t{:<19}{:<10}'.format(str(subnet[0]), ' ({:,})'.format(subnet[1])))

        print('')
        if self.eternal_blue_count > 0:
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
        port_scan_report = []

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

                open_port_count = 0

                with open(zmap_out_file, 'w') as f:
                    for line in io.TextIOWrapper(self.secondary_zmap_process.stdout, encoding='utf-8'):
                        ip = line.strip()
                        print('[+] {:<23}{:<10}'.format('{}:{}'.format(self.hosts[ip]['IP Address'], port), self.hosts[ip]['Hostname']))
                        f.write(ip + '\n')
                        self.hosts[ip].open_ports.add(port)
                        open_port_count += 1

                port_scan_report.append('\n[+] Wrote port {} results to {}'.format(port, zmap_out_file))
                port_scan_report.append('[+] {:,} hosts with port {} open ({:.2f}%)'.format(\
                    open_port_count, port, (open_port_count / len(self.hosts) * 100)))

            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching zmap: {}\n'.format(str(e)))
                sys.exit(1)

            finally:
                self.secondary_zmap_started = False
                self.secondary_zmap_process = None

        return (zmap_out_file, port_scan_report)


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


    def get_network_delta(self, sub_range_file, netmask=24):
        '''
        takes file containing newtork hosts/ranges
        returns dictionary:
        {
            network: host_count,
            ...
        }
        '''

        stray_hosts = self.get_host_delta(sub_range_file)

        stray_networks = list(self.summarize_online_hosts(hosts=stray_hosts, netmask=netmask).items())
        stray_networks.sort(key=lambda x: x[1], reverse=True)

        return stray_networks



    def get_host_delta(self, sub_host_file):

        sub_ranges = set()
        with open(sub_host_file) as f:
            lines = [line.strip() for line in f.readlines()]
            for line in lines:
                try:
                    for network in str_to_network(line):
                        sub_ranges.add(network)
                except:
                    continue

        master_ranges = [i[0] for i in self.summarize_online_hosts()]

        hosts = [ipaddress.ip_address(i) for i in self.hosts]

        stray_hosts = []
        for h in hosts:
            if not any([h in s for s in sub_ranges]):
                stray_hosts.append(h)

        stray_hosts.sort()
        return stray_hosts


    def summarize_online_hosts(self, hosts=None, netmask=24):

        if hosts is None:
            hosts = self.hosts

        subnets = dict()

        for ip in hosts:

            subnet = ipaddress.ip_network(str(ip) + '/{}'.format(netmask), strict=False)

            try:
                subnets[subnet] += 1
            except KeyError:
                subnets[subnet] = 1

        return subnets



    @staticmethod
    def _deduplicate_net_ranges(net_ranges):
        '''
        currently unused, but potentially useful
        can't bring myself to delete it
        '''

        net_ranges = [ipaddress.ip_network(net) for net in net_ranges]
        net_ranges.sort(key=lambda x: x.netmask, reverse=True)
        deduplicated_ranges = []

        for i in range(len(net_ranges)):

            net_range = net_ranges[i]
            # if network doesn't overlap with any larger ones
            if not any([net_range.overlaps(n) for n in net_ranges[i+1:]]):
                deduplicated_ranges.append(net_range)

        return deduplicated_ranges



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
        self.output_file        = str(work_dir / 'nmap_output')
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

        return '{:<16}{}'.format(self['IP Address'], self['Hostname'])



def main(options):

    if os.geteuid() != 0:
        sys.stderr.write('[!] Must be root\n')
        sys.exit(2)



    # resolve symlinks
    options.work_dir = options.work_dir.resolve()

    # default CSV output
    if options.csv_file is None:
        options.csv_file = options.work_dir / 'asset_inventory.csv'

    # if starting fresh rename working directory to ".bak"
    if options.start_fresh:
        backup_work_dir = Path(str(options.work_dir) + '_{date:%Y-%m-%d_%H:%M:%S}.bak'.format( date=datetime.now() ))
        try:
            old_dir = str(options.work_dir)
            options.work_dir.rename(backup_work_dir)
            print('[+] Backed up {} to {}'.format(old_dir, str(backup_work_dir)))
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
        port_scan_report = []
        for port in options.ports:
            report = z.scan_online_hosts(port)[1]
            port_scan_report += report

        print('')
        for line in port_scan_report:
            print(line)

    # print summary
    z.report(netmask=options.netmask)

    # calculate deltas if requested:
    if options.diff:
        stray_hosts = []
        stray_networks = []

        stray_networks = z.get_network_delta(options.diff, netmask=options.netmask)
        stray_networks_csv = './network_diff_{date:%Y-%m-%d_%H%M%S}.csv'.format( date=datetime.now())
        print('')
        print('[+] {:,} active network(s) not found in {}'.format(len(stray_networks), str(options.diff)))
        print('[+] Writing data to {}'.format(stray_networks_csv))
        print('=' * 50)
        with open(stray_networks_csv, 'w', newline='') as f:
            csv_file = csv.DictWriter(f, fieldnames=['Network', 'Host Count'])
            csv_file.writeheader()
            for network in stray_networks:
                csv_file.writerow({'Network': str(network[0]), 'Host Count': str(network[1])})
                #print('\t{:<16}{}'.format(str(network[0]), network[1]))
                print('\t{:<19}{:<10}'.format(str(network[0]), ' ({:,})'.format(network[1])))

        stray_hosts = z.get_host_delta(options.diff)
        stray_hosts_csv = './host_diff_{date:%Y-%m-%d_%H%M%S}.csv'.format( date=datetime.now())
        print('')
        print('[+] {:,} alive host(s) not found in {}'.format(len(stray_hosts), str(options.diff)))
        print('[+] Writing data to {}'.format(stray_hosts_csv))
        print('=' * 50)
        with open(stray_hosts_csv, 'w', newline='') as f:
            csv_file = csv.DictWriter(f, fieldnames=['IP Address', 'Hostname'])
            csv_file.writeheader()
            for host in stray_hosts:
                host = z.hosts[str(host)]
                csv_file.writerow({'IP Address': host['IP Address'], 'Hostname': host['Hostname']})
                print('\t{}'.format(str(host)))

        print('\n')
        # if more than 5 percent of hosts are strays, or you have more than one stray network
        if len(stray_hosts)/len(z.hosts) > .05 or len(stray_networks) > 1:
            print(' "Your asset management is bad and you should feel bad"')
            print('')

    print('[+] CSV file written to {}'.format(options.csv_file))

    try:
        z.stop()

        # pickle Zmap object to save state
        with open(saved_state, 'wb') as f:
            print('[+] Saving state to {}'.format(str(saved_state)))
            pickle.dump(z, f)
    except:
        pass



def str_to_network(s):
    '''
    takes either CIDR or range notation as string
    generates ip_network objects
    '''

    try:
        if '-' in s:
            start, end = s.split('-')[:2]
            for i in ipaddress.summarize_address_range(ip_address(start), ip_address(end)):
                yield i
        else:
            yield ipaddress.ip_network(s, strict=False)

    except ValueError:
        pass


def parse_target_args(targets):
    '''
    takes 
    '''

    networks = set()

    for network_list in targets:
        for network in network_list:
            networks.add(network)

    networks = list(networks)
    networks.sort()
    return networks



if __name__ == '__main__':

    default_bandwidth = '750K'
    default_work_dir = Path.home() / '.asset_inventory'
    default_cidr_mask = 24

    parser = argparse.ArgumentParser("Scan private IP ranges, output to CSV")
    parser.add_argument('-t', '--targets', type=str_to_network, nargs='+', default=[['10.0.0.0/8'], ['172.16.0.0/12'], ['192.168.0.0/16']], help='target network(s) to scan', metavar='STR')
    parser.add_argument('-B', '--bandwidth', default=default_bandwidth,         help='max egress bandwidth (default {})'.format(default_bandwidth), metavar='STR')
    parser.add_argument('--blacklist',                                          help='a file containing hosts to exclude from scanning', metavar='FILE')
    parser.add_argument('-w', '--csv-file',                                     help='output CSV file', metavar='CSV_FILE')
    parser.add_argument('-f', '--start-fresh',          action='store_true',    help='don\'t load results from previous scans')
    parser.add_argument('-p', '--ports', nargs='+', type=int,                   help='port-scan online hosts')
    parser.add_argument('-e', '--check-eternal-blue',   action='store_true',    help='scan for EternalBlue')
    parser.add_argument('--work-dir',               type=Path,                  help='custom working directory', metavar='DIR')
    parser.add_argument('-d', '--diff',             type=Path,                  help='show differences between scan results and IPs/networks from file', metavar='FILE')
    parser.add_argument('-n', '--netmask', type=int, default=default_cidr_mask, help='summarize networks with this CIDR mask (default: {})'.format(default_cidr_mask))

    try:

        options = parser.parse_args()
        options.targets = parse_target_args(options.targets)
        if not options.targets:
            sys.stderr.write('\n[!] No valid targets\n')
            sys.exit(1)

        assert 0 <= options.netmask <=32, "Invalid netmask"

        scan_uid = '_'.join([str(t).replace('/', '-') for t in options.targets])
        if options.work_dir is None:
            # unique identifier based on scan targets
            options.work_dir = default_work_dir / scan_uid
        else:
            options.work_dir = options.work_dir / scan_uid


        main(options)


    except (argparse.ArgumentError, ValueError, AssertionError) as e:
        sys.stderr.write('\n[!] {}\n'.format(str(e)))
        sys.exit(2)

    except KeyboardInterrupt:
        sys.stderr.write('\n[!] Interrupted\n')
        sys.exit(1)