#!/usr/bin/env python3

# by TheTechromancer

import io
import os
import csv
import sys
import tempfile
import ipaddress
from time import sleep
from lib.host import *
import subprocess as sp
from pathlib import Path
from lib.host import Host
from datetime import datetime
import xml.etree.cElementTree as xml # for parsing Nmap output


class Zmap:

    def __init__(self, targets, bandwidth, work_dir, skip_ping=False, blacklist=None, interface=None, gateway_mac=None):

        # target-specific open port counters
        # nested dictionary in format:
        # { target: { port: open_count ... } ... }
        self.targets = dict()
        for target in targets:
            if type(target) == ipaddress.IPv4Address or type(target) == ipaddress.IPv4Network:
                self.targets[target]        = dict()
            else:
                raise ValueError('Invalid type for target: {}'.format(str(type(target))))

        # global open port counters
        # dictionary in format:
        # { port: open_count ... }
        self.open_ports                 = dict()

        # stores all known hosts
        # dictionary in format:
        # { ip_address(): Host() ... }
        self.hosts                      = dict()

        if interface is None:
            self.interface_arg          = []
        else:
            self.interface_arg          = ['--interface={}'.format(str(interface))]

        if gateway_mac is None:
            self.gateway_mac_arg        = []
        else:
            self.gateway_mac_arg        = ['--gateway-mac={}'.format(str(gateway_mac))]

        self.zmap_ping_targets          = set()
        self.eternal_blue_count         = 0
        self.host_discovery_finished    = False

        self.zmap_ping_file             = str(work_dir / 'zmap_ping_{date:%Y-%m-%d_%H-%M-%S}.txt'.format(date=datetime.now()))
        self.online_hosts_file          = str(work_dir / 'zmap_all_online_hosts.txt')

        self.skip_ping                  = skip_ping

        # windows service friendly names for CSV
        self.services                   = []

        self.update_config(bandwidth, work_dir, blacklist)
        self.load_scan_cache()


    def start(self):

        if self.zmap_ping_targets and not self.primary_zmap_started and not self.skip_ping:

            self.primary_zmap_started = True

            zmap_command = ['zmap', '--blacklist-file={}'.format(self.blacklist), \
                '--bandwidth={}'.format(self.bandwidth), \
                '--probe-module=icmp_echoscan'] + self.interface_arg + \
                self.gateway_mac_arg + [str(t) for t in self.zmap_ping_targets]

            print('\n[+] Running zmap ping scan:\n\t> {}\n'.format(' '.join(zmap_command)))

            try:
                self.primary_zmap_process = sp.Popen(zmap_command, stdout=sp.PIPE)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching zmap: {}\n'.format(str(e)))
                sys.stderr.flush()
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



    def hosts_sorted(self, hosts=None):

        hosts_sorted = []

        if hosts is None:
            hosts_sorted = list(self.hosts.values())
        else:
            for host in hosts:
                host = Host(host)
                try:
                    # try to get hostname
                    host['Hostname'] = self.hosts[host['IP Address']]['Hostname']
                except KeyError:
                    pass
                finally:
                    hosts_sorted.append(host)

        hosts_sorted.sort(key=lambda x: ipaddress.ip_address(x['IP Address']))
        return hosts_sorted


    def check_eternal_blue(self):

        print('\n[+] Scanning for EternalBlue')

        nmap_input_file = self.scan_online_hosts(port=445)

        if nmap_input_file is None:
            return

        else:
            for ip, vulnerable in Nmap(nmap_input_file, work_dir=self.work_dir / 'nmap'):
                if vulnerable:
                    self.eternal_blue_count += 1
                    if not ip in self.hosts:
                        self.hosts[ip] = Host(ip)
                    self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
                else:
                    self.hosts[ip]['Vulnerable to EternalBlue'] = 'No'


    def report(self, netmask=24):

        print('\n\n[+] RESULTS:')
        print('=' * 60 + '\n')
        print('[+] Total Online Hosts: {:,}'.format(len(self.hosts)))
        print('[+] Summary of Subnets:')
        summarized_hosts = list(self.summarize_online_hosts(netmask=netmask).items())
        # sort by network first
        summarized_hosts.sort(key=lambda x: x[0])
        # then sort by host count
        summarized_hosts.sort(key=lambda x: x[1], reverse=True)
        for subnet in summarized_hosts:
            print('\t{:<19}{:<10}'.format(str(subnet[0]), ' ({:,} | {:.2f}%)'.format(subnet[1], subnet[1]/len(self.hosts)*100)))

        print('')
        for port, open_port_count in self.open_ports.items():
            print('[+] {:,} host(s) with port {} open ({:.2f}%)'.format(\
                    open_port_count, port, (open_port_count / len(self.hosts) * 100)))

        if self.eternal_blue_count > 0:
            print('\n')
            print('[+] Vulnerable to EternalBlue: {:,}\n'.format(self.eternal_blue_count))
            for host in self.hosts.values():
                if host['Vulnerable to EternalBlue'] == 'Yes':
                    print('\t{}'.format(str(host)))
            print('')

        print('')


    def scan_online_hosts(self, port):

        # make sure host discovery has finished
        for h in self:
            pass

        port = int(port)
        zmap_out_file = self.work_dir / 'zmap_port_{}_{date:%Y-%m-%d_%H-%M-%S}.txt'.format(port, date=datetime.now())
        zmap_whitelist_file = self.work_dir / '.zmap_tmp_whitelist_port_{}.txt'.format(port)
        targets = [t[0] for t in self.targets.items() if port not in t[1]]

        # fill target-specific port counts
        # so we at least know they're scanned
        # necessary because currently all targets are wrapped together
        for target in targets:
            if not port in self.targets[target]:
                self.targets[target][port] = 0

        if self.skip_ping:
            zmap_targets = [str(t) for t in targets]

        else:
            zmap_targets = ['--whitelist-file={}'.format(str(zmap_whitelist_file))]
            # write target IPs to file for zmap
            hosts_written = False
            with open(str(zmap_whitelist_file), 'w') as f:
                for target in targets:
                    for ip in self.hosts:
                        if ip in target:
                            #print(str(ip), ' is in ', str(target))
                            hosts_written = True
                            f.write(str(ip) + '\n')
                        else:
                            #print(str(ip), ' is not in ', str(target))
                            pass

            if not hosts_written:
                print('[+] No hosts to scan on port {}'.format(port))
                return
            else:
                print('[+] Scanning {:,} hosts on port {}'.format(len(self.hosts), port))

        self.secondary_zmap_started = True

        # run the main scan if it hasn't already completed
        for host in self:
            pass

        if not zmap_targets:
            print('[!] No targets to scan')
            return

        else:

            zmap_command = ['zmap', '--blacklist-file={}'.format(self.blacklist), \
                '--bandwidth={}'.format(self.bandwidth), '--target-port={}'.format(port)] + \
                self.gateway_mac_arg + self.interface_arg + zmap_targets

            print('\n[+] Running zmap SYN scan on port {}:\n\t> {}\n'.format(port, ' '.join(zmap_command)))

            try:

                self.secondary_zmap_process = sp.Popen(zmap_command, stdout=sp.PIPE)
                sleep(2)

                open_port_count = 0

                hosts_written = False
                with open(zmap_out_file, 'w') as f:
                    for line in io.TextIOWrapper(self.secondary_zmap_process.stdout, encoding='utf-8'):

                        try:
                            ip = ipaddress.ip_address(line.strip())
                        except ValueError:
                            continue

                        # make sure the host exists
                        if not ip in self.hosts:
                            self.hosts[ip] = Host(ip)

                        print('[+] {:<23}{:<10}'.format('{}:{}'.format(str(ip), port), self.hosts[ip]['Hostname']))

                        if port not in self.hosts[ip].open_ports:
                            self.hosts[ip].open_ports.add(port)
                            open_port_count += 1

                            f.write(str(ip) + '\n')
                            hosts_written = True

                if not hosts_written:
                    print('[!] No new hosts found with port {} open'.format(port))
                    return

                if open_port_count > 0:
                    try:
                        self.open_ports[port] += open_port_count
                    except KeyError:
                        self.open_ports[port] = open_port_count

            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching zmap: {}\n'.format(str(e)))
                sys.exit(1)

            finally:
                self.secondary_zmap_started = False
                self.secondary_zmap_process = None
                # remove temporary whitelist file
                # zmap_whitelist_file.unlink()

        return zmap_out_file


    def update_config(self, bandwidth, work_dir, blacklist=None):

        self.bandwidth              = str(bandwidth).upper()
        self.primary_zmap_process   = None
        self.primary_zmap_started   = False
        self.secondary_zmap_process = None
        self.secondary_zmap_started = False
        self.work_dir               = Path(work_dir)

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
                except ValueError as e:
                    print('[!] Bad entry in {}:'.format(str(sub_host_file)))
                    print('     {}'.format(str(e)))

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



    def write_csv(self, csv_file=None, hosts=None):

        try:

            csv_writer, f = self._make_csv_writer(csv_file)

            # make sure initial discovery scan has completed
            for host in self:
                pass

            with open(self.online_hosts_file, 'w') as f:
                for host in self.hosts_sorted(hosts):

                    self._write_csv_line(csv_writer, host)
                    f.write(host['IP Address'] + '\n')

        finally:
            try:
                f.close()
            except:
                pass



    def dump_scan_cache(self):

        try:
            # dictionary in the form { ip_network: (csv_writer, csv_file_handle) }
            targets = dict()

            for target in self.targets:
                target_id = str(target).replace('/', '-')
                target_dir = self.work_dir / target_id
                target_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                target_file = target_dir / 'state.csv'
                targets[target] = (None, target_file)


            for target in targets:

                if targets[target][0] is None:
                    target_file = targets[target][1]
                    targets[target] = self._make_csv_writer(csv_file=target_file)

                for ip, host in self.hosts.items():
                    if ip in target:
                        csv_writer = targets[target][0]
                        self._write_csv_line(csv_writer, host, ports=self.targets[target])

        finally:
            try:
                # close file handles
                for target in targets:
                    targets[target][1].close()
            except:
                pass



    def load_scan_cache(self):

        print('[+] Loading scan cache')

        cached_targets = []

        try:
            for target_dir in next(os.walk(self.work_dir))[1]:

                try:
                    target_net = ipaddress.ip_network(target_dir.replace('-', '/'))
                    print('[+] Found folder: {}'.format(str(self.work_dir / target_dir)))
                except ValueError:
                    # print('[!] Found invalid cached folder: {}, skipping'.format(str(target_dir)))
                    continue

                if not any([target_net == t for t in self.targets]):
                    print('[i]  - directory does not match any given target')

                else:
                    target_dir = self.work_dir / target_dir

                    try:
                        for cache_file in next(os.walk(target_dir))[2]:
                            if cache_file.endswith('.csv'):
                                #print('[+] Reading {}'.format(str(cache_file)))
                                empty_file, open_ports = self.read_csv(target_dir / cache_file)

                                try:
                                    self.targets[target_net].update(open_ports)
                                except KeyError:
                                    self.targets[target_net] = open_ports

                                if not empty_file:
                                    print('[+]  - contains cached data'.format(str(target_net)))
                                    cached_targets.append(target_net)
                                else:
                                    print('[!] - cache file appears to be empty')

                    except StopIteration:
                        continue

        except StopIteration:
            return

        for target in self.targets:
            if not target in cached_targets:
                self.zmap_ping_targets.add(target)




    def read_csv(self, csv_file):
        '''
        takes name of CSV file to read
        injests contents
        returns number of hosts therein
        '''

        new_hosts = 0
        empty_file = True
        open_ports = dict()

        # default CSV output
        if csv_file is None:
            csv_file = self.work_dir / 'state.csv'

        with open(str(csv_file), newline='') as f:
            c = csv.DictReader(f)

            for line in c:

                try:
                    ip = ipaddress.ip_address(line['IP Address'])
                    empty_file = False
                except ValueError:
                    #print('[!] Invalid IP address: {}'.format(str(line['IP Address'])))
                    continue

                host = Host(ip=ip, hostname=line['Hostname'])
                vulnerable_to_eb = line['Vulnerable to EternalBlue']
                if vulnerable_to_eb.capitalize() == 'Yes':
                    self.eternal_blue_count += 1
                host['Vulnerable to EternalBlue'] = vulnerable_to_eb

                # if we've already seen this host, merge it
                if ip not in self.hosts:
                    self.hosts[ip] = host
                    new_hosts += 1
                else:
                    self.hosts[ip].merge(host)

                for field in c.fieldnames:
                    if field.endswith('/tcp'):
                        port = int(field.split('/')[0])
                        if line[field] == 'Open':
                            if not port in self.open_ports:
                                self.open_ports[port] = 0

                            if port not in self.hosts[ip].open_ports:
                                self.hosts[ip].open_ports.add(port)
                                self.open_ports[port] += 1

                            try:
                                open_ports[port] += 1
                            except KeyError:
                                open_ports[port] = 1


        return (empty_file, open_ports)




    def _make_csv_writer(self, csv_file=None):
        '''
        take csv filename
        returns (csv_dictwriter, file_handle)
        '''

        # default CSV output
        if csv_file is None:
            csv_file = self.work_dir / 'asset_inventory.csv'

        f = open(csv_file, 'w', newline='')
        csv_writer = csv.DictWriter(f, fieldnames=['IP Address', 'Hostname', 'Vulnerable to EternalBlue'] + \
            ['{}/tcp'.format(port) for port in self.open_ports] + self.services, extrasaction='ignore')
        csv_writer.writeheader()

        return (csv_writer, f)



    def _write_csv_line(self, csv_writer, host, ports=None):

        if ports is None:
            ports = self.open_ports

        if not type(host) == Host:
            try:
                host = self.hosts[ipaddress.ip_address(host)]
            except ValueError:
                return

        # see which target range the host is from
        # so we know whether the port is closed or unscanned
        ip = ipaddress.ip_address(host['IP Address'])
        in_target = None
        for target in self.targets:
            try:
                if ip in target:
                    #print(str(ip), ' is in ', str(target))
                    in_target = target
                    break
            except TypeError as e:
                '''
                Traceback (most recent call last):
                  File "./zmap_asset_inventory.py", line 275, in <module>
                    main(options)
                  File "./zmap_asset_inventory.py", line 133, in main
                    z.write_csv(csv_file=options.csv_file)
                  File "/root/Downloads/zmap-asset-inventory/lib/scan.py", line 382, in write_csv
                    self._write_csv_line(csv_writer, host)
                  File "/root/Downloads/zmap-asset-inventory/lib/scan.py", line 570, in _write_csv_line
                    if ip in target:
                TypeError: 'in <string>' requires string as left operand, not IPv4Address
                '''
                print('target: {}, {}'.format(str(target), str(type(target))))
                print(str(e))
                continue

        open_ports = dict()
        for port in ports:
            port_state = 'Unknown'
            if port in host.open_ports:
                port_state = 'Open'
            elif in_target is not None:
                if port in self.targets[in_target]:
                    #print(str(port), ' is in ', str(self.targets))
                    port_state = 'Closed'

            open_ports['{}/tcp'.format(port)] = port_state

        host.update(open_ports)
        try:
            csv_writer.writerow(host)
        except ValueError as e:
            # port is in self.open_ports but not in self.targets
            print('[!] {}'.format(str(e)))



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

        for host in self.hosts.values():
            #f.write(host['IP Address'] + '\n')
            yield host

        if self.zmap_ping_targets and not self.primary_zmap_started and not self.skip_ping:

            with open(self.zmap_ping_file, 'w') as f:

                self.start()
                sleep(1)
                for line in io.TextIOWrapper(self.primary_zmap_process.stdout, encoding='utf-8'):
                    try:
                        ip = ipaddress.ip_address(line.strip())
                    except ValueError:
                        continue
                    host = Host(ip, resolve=True)
                    print('[+] {:<17}{:<10} '.format(host['IP Address'], host['Hostname']))
                    self.hosts[ip] = host
                    f.write(str(ip) + '\n')
                    yield host

                self.zmap_ping_targets.clear()

        self.primary_zmap_started = False
        self.host_discovery_finished = True




class Nmap:

    def __init__(self, targets_file, work_dir):

        self.process            = None
        self.output_file        = str(work_dir / 'nmap_ms17-010')
        self.finished           = False
        self.targets_file       = str(targets_file)

        self.hosts = dict()


    def __iter__(self):
        '''
        Yields IP and boolean representing whether or not it's vulnerable
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
            tree = xml.parse(self.output_file + '.xml')

            for host in tree.findall('host'):
                pass

                ip = None
                for address in host.findall('address'):
                    if address.attrib['addrtype'] == 'ipv4':
                        try:
                            ip = ipaddress.ip_address(address.attrib['addr'])
                        except ValueError:
                            continue
                        break

                if ip is None:
                    continue

                else:
                    self.hosts[ip] = Host(ip)
                    for hostscript in host.findall('hostscript'):
                        for script in hostscript.findall('script'):
                            if script.attrib['id'] == 'smb-vuln-ms17-010' and 'VULNERABLE' in script.attrib['output']:
                                self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
                                yield (ip, True)
                            else:
                                self.hosts[ip]['Vulnerable to EternalBlue'] = 'No'
                                yield (ip, False)

            self.finished = True

        else:
            for ip, host in self.hosts.items():
                yield (ip, host['Vulnerable to EternalBlue'] == 'Yes')

        print('[+] Saved Nmap results to {}.*'.format(self.output_file))
