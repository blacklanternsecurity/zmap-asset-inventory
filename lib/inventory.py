#!/usr/bin/env python3.7

# by TheTechromancer

import io
import os
import csv
import sys
import tempfile
import ipaddress
from time import sleep
import subprocess as sp
from shutil import which
from pathlib import Path
from datetime import datetime

from .host import *


class Inventory:

    def __init__(self, targets, bandwidth, work_dir, resolve=True, force_resolve=False, skip_ping=False, force_ping=False, blacklist=None, whitelist=None, interface=None, gateway_mac=None):

        # target-specific open port counters
        # nested dictionary in format:
        # { target: { port: open_count ... } ... }
        self.targets = dict()
        for target in targets:
            try:
                self.targets[ipaddress.ip_network(target)] = dict()
            except ValueError:
                raise ValueError('Invalid target: {}'.format(str(target)))

        # global open port counters
        # dictionary in format:
        # { port: open_count ... }
        self.open_ports                 = dict()

        # stores all known hosts
        # dictionary in format:
        # { ip_address(): Host() ... }
        self.hosts                      = dict()

        self.modules                    = []
        self.active_modules             = []

        # whether or not to perform reverse DNS lookups
        self.resolve                    = resolve
        self.force_resolve              = force_resolve

        if interface is None:
            self.interface_arg          = []
        elif interface.startswith('tun'):
            self.interface_arg          = ['--interface={}'.format(str(interface)), '--vpn']
        else:
            self.interface_arg          = ['--interface={}'.format(str(interface))]

        if gateway_mac is None:
            self.gateway_mac_arg        = []
        else:
            self.gateway_mac_arg        = ['--gateway-mac={}'.format(str(gateway_mac))]

        self.zmap_ping_targets          = set()
        self.eternal_blue_count         = 0
        self.host_discovery_finished    = False

        self.zmap_ping_file             = str(work_dir / 'zmap/zmap_ping_{date:%Y-%m-%d_%H-%M-%S}.txt'.format(date=datetime.now()))
        self.online_hosts_file          = str(work_dir / 'zmap/zmap_all_online_hosts.txt')

        self.skip_ping                  = skip_ping
        self.force_ping                 = force_ping

        self.update_config(bandwidth, work_dir, blacklist, whitelist)

        # make sure zmap is installed
        if not which('zmap'):
            sys.stderr.write('\n[!] Please install zmap! :)\n\n')
            sys.exit(1)


    def start(self):

        if self.zmap_ping_targets and not self.primary_zmap_started and \
            ((not self.skip_ping) or (self.force_ping)):

            self.primary_zmap_started = True

            zmap_command = ['zmap', '--cooldown-time=3', '--blacklist-file={}'.format(self.blacklist_arg), \
                '--bandwidth={}'.format(self.bandwidth), \
                '--probe-module=icmp_echoscan'] + self.interface_arg + \
                self.gateway_mac_arg + self.whitelist_arg + \
                ([] if self.whitelist_arg else [str(t) for t in self.zmap_ping_targets])

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
            for ip in hosts:
                hostname = ''
                try:
                    # try to get hostname
                    hostname = self.hosts[ipaddress.ip_address(ip)]['Hostname']
                except KeyError:
                    pass
                finally:
                    hosts_sorted.append(Host(ip, hostname))

        hosts_sorted.sort(key=lambda x: ipaddress.ip_address(x['IP Address']))
        return hosts_sorted


    def run_modules(self):

        # make sure the right programs are installed
        for module in list(self.active_modules):
            progs_to_install = module.check_progs()
            if progs_to_install:
                self.active_modules.remove(module)
                sys.stderr.write('\n[!] Error running module "{}"\n'.format(module.name))
                sys.stderr.write('[!] Please ensure the following are installed and in your $PATH:\n')
                sys.stderr.write('\n'.join([('     - ' + str(e)) for e in progs_to_install]) + '\n\n')

        for module in self.active_modules:
            module.run(self)


    def module_reports(self):

        for module in self.active_modules:
            module.report(self)


    def brute_ssh(self):

        print('\n[+] Checking for default SSH creds')

        patator_input_file, new_ports_found = self.scan_online_hosts(port=22)

        patator_targets = [h.ip for h in self.hosts.values() if 22 in h.open_ports]

        patator = Patator(patator_targets, work_dir=self.work_dir / 'patator')
        patator.scan()



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
            print('\t{:<19}{:<10}'.format(str(subnet[0]), ' ({:,} | {:.1f}%)'.format(subnet[1], subnet[1]/len(self.hosts)*100)))

        print('')
        open_port_counts = list(self.open_ports.items())
        open_port_counts.sort(key=lambda x: x[1], reverse=True)
        for port, open_port_count in open_port_counts:
            print('[+] {:,} host(s) with port {} open ({:.1f}%)'.format(\
                    open_port_count, port, (open_port_count / len(self.hosts) * 100)))

        print('')


    def scan_online_hosts(self, port):

        # make sure host discovery has finished
        for h in self:
            pass

        port = int(port)
        zmap_out_file = self.work_dir / 'zmap/zmap_port_{}_{date:%Y-%m-%d_%H-%M-%S}.txt'.format(port, date=datetime.now())
        zmap_whitelist_file = self.work_dir / 'zmap/zmap_tmp_whitelist_port_{}.txt'.format(port)
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
            if self.whitelist_arg:
                zmap_targets = self.whitelist_arg
            else:
                zmap_targets = ['--whitelist-file={}'.format(zmap_whitelist_file)]
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
                    return (None, 0)
                else:
                    print('[+] Scanning {:,} hosts on port {}'.format(len(self.hosts), port))

        self.secondary_zmap_started = True

        # run the ping scan if it hasn't already completed
        for host in self:
            pass

        if not zmap_targets:
            print('[!] No targets to scan on port {}'.format(port))
            return (None, 0)

        else:

            zmap_command = ['zmap', '--cooldown-time=3', '--blacklist-file={}'.format(self.blacklist_arg), \
                '--bandwidth={}'.format(self.bandwidth), '--target-port={}'.format(port)] + \
                self.gateway_mac_arg + self.interface_arg + self.whitelist_arg + \
                ([] if self.whitelist_arg else zmap_targets)

            print('\n[+] Running zmap SYN scan on port {}:\n\t> {}\n'.format(port, ' '.join(zmap_command)))

            try:

                self.secondary_zmap_process = sp.Popen(zmap_command, stdout=sp.PIPE)
                sleep(2)

                open_port_count = 0

                new_ports_found = False
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

                        # write IP to file even if the port was found previously
                        # for scanning eternal blue, etc.
                        f.write(str(ip) + '\n')

                        if port not in self.hosts[ip].open_ports:
                            self.hosts[ip].open_ports.add(port)
                            open_port_count += 1
                            new_ports_found = True

                if not new_ports_found:
                    print('[!] No new hosts found with port {} open'.format(port))

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

        return (zmap_out_file, new_ports_found)


    def update_config(self, bandwidth, work_dir, blacklist=None, whitelist=None):

        self.bandwidth              = str(bandwidth).upper()
        self.primary_zmap_process   = None
        self.primary_zmap_started   = False
        self.secondary_zmap_process = None
        self.secondary_zmap_started = False
        self.work_dir               = Path(work_dir)

        # validate bandwidth arg
        if not any([self.bandwidth.endswith(s) for s in ['K', 'M', 'G']]):
            raise ValueError('Invalid bandwidth: {}'.format(self.bandwidth))


        ### BLACKLIST ###

        self.blacklist = []

        # validate blacklist arg
        if blacklist is None:
            blacklist = work_dir / 'zmap/zmap_tmp_blacklist'
            blacklist.touch(mode=0o644, exist_ok=True)
            self.blacklist_arg = str(blacklist)
        else:
            self.blacklist_arg = Path(blacklist).resolve()
            if not self.blacklist_arg.is_file():
                raise ValueError('Cannot process blacklist file: {}'.format(str(self.blacklist_arg)))
            else:
                self.blacklist_arg = str(self.blacklist_arg)

            with open(self.blacklist_arg) as f:
                for line in f.readlines():
                    line = line.strip()
                    try:
                        entry = ipaddress.ip_network(line, strict=False)
                        if not entry in self.blacklist:
                            self.blacklist.append(entry)
                    except ValueError:
                        continue


        ### WHITELIST ###

        # list of ip_network objects
        self.whitelist = []

        if whitelist is None:
            # filename of whitelist file (for zmap, etc.)
            self.whitelist_file = None
            # whitelist argument to be passed to zmap
            self.whitelist_arg = []

        else:
            self.whitelist_file = Path(whitelist).resolve()
            if not self.whitelist_file.is_file():
                raise ValueError('Cannot process whitelist file: {}'.format(self.whitelist_file))
            else:
                self.whitelist_arg = ['--whitelist-file={}'.format(str(self.whitelist_file))]

            with open(self.whitelist_file) as f:
                for line in f.readlines():
                    line = line.strip()
                    try:
                        entry = ipaddress.ip_network(line, strict=False)
                        if not entry in self.whitelist:
                            self.whitelist.append(entry)
                    except ValueError:
                        continue


    def get_network_delta(self, sub_host_file, netmask=24):
        '''
        takes file containing newtork hosts/ranges
        returns list:
        [
            (network:], host_count),
            ...
        ]
        '''

        sub_ranges = set()
        with open(sub_host_file) as f:
            lines = [line.strip() for line in f.readlines()]
            for line in lines:
                try:
                    for network in str_to_network(line):
                        sub_ranges.add(ipaddress.ip_network((network.network_address, netmask), strict=False))
                except ValueError as e:
                    print('[!] Bad entry in {}:'.format(str(sub_host_file)))
                    print('     {}'.format(str(e)))


        hosts = [ipaddress.ip_address(i) for i in self.hosts]

        stray_networks = dict()
        for h in hosts:
            if not any([h in s for s in sub_ranges]):
                host_net = ipaddress.ip_network((h, netmask), strict=False)
                try:
                    stray_networks[host_net] += 1
                except KeyError:
                    stray_networks[host_net] = 1

        stray_networks = list(stray_networks.items())
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
        if not self.force_resolve:
            print('[+] NOTE: you can force DNS lookups on cached hosts with --force-dns')

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
                                    print('[+]  - empty (use --force-ping to scan again)')
                                    cached_targets.append(target_net)

                    except StopIteration:
                        continue

        except StopIteration:
            return

        print('[+] Loaded {:,} hosts from cache'.format(len(self.hosts)))

        for target in self.targets:
            if not target in cached_targets or self.force_ping:
                self.zmap_ping_targets.add(target)




    def read_csv(self, csv_file):
        '''
        takes name of CSV file to read
        ingests contents
        returns number of hosts therein
        '''

        new_hosts = 0
        empty_file = True
        open_ports = dict()

        with open(str(csv_file), newline='') as f:
            c = csv.DictReader(f)

            for line in c:

                line = dict(line)

                try:
                    ip = ipaddress.ip_address(line['IP Address'])
                    empty_file = False
                except ValueError:
                    #print('[!] Invalid IP address: {}'.format(str(line['IP Address'])))
                    continue

                host = Host(ip=line['IP Address'], hostname=line['Hostname'], resolve=self.force_resolve)
                for module in self.modules:
                    module.read_host(line, host)

                # if we've already seen this host, merge it
                if ip not in self.hosts:
                    self.hosts[ip] = host
                    new_hosts += 1
                else:
                    self.hosts[ip].merge(host)

                for key, value in line.items():
                    value = value.strip()
                    if key.endswith('/tcp'):
                        port = int(key.split('/')[0])
                        if value.lower() == 'open':
                            if not port in self.open_ports:
                                self.open_ports[port] = 0

                            if port not in self.hosts[ip].open_ports:
                                self.hosts[ip].open_ports.add(port)
                                self.open_ports[port] += 1

                            try:
                                open_ports[port] += 1
                            except KeyError:
                                open_ports[port] = 1

                    # all other values are loaded here, to preserve module output between executions
                    # even if the module is not loaded
                    # currently, a module's read_host() method is not needed
                    #elif value:
                    #    host.update({key: value})


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

        # build CSV headers
        fieldnames = ['IP Address', 'Hostname']
        for m in self.modules:
            fieldnames += m.csv_headers
        fieldnames += ['{}/tcp'.format(port) for port in self.open_ports]

        csv_writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
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



    def _valid_host(self, host):
        '''
        given a host, return whether or not it's valid based on whitelist and blacklist
        '''

        if type(host) == str:
            host = ipaddress.ip_address(host)
        elif type(host) == Host:
            host = host.ip

        if not any([host in network for network in self.blacklist]):
            if not self.whitelist or any([host in network for network in self.whitelist]):
                if any([host in target for target in self.targets]):
                    return True

        return False



    def __iter__(self):

        for host in self.hosts.values():
            #f.write(host['IP Address'] + '\n')
            if self._valid_host(host):
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
                    host = Host(ip, resolve=self.resolve)
                    print('[+] {:<17}{:<10} '.format(host['IP Address'], host['Hostname']))
                    self.hosts[ip] = host
                    f.write(str(ip) + '\n')
                    if self._valid_host(host):
                        yield host

                self.zmap_ping_targets.clear()

        self.primary_zmap_started = False
        self.host_discovery_finished = True