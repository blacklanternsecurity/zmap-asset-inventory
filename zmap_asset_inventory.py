#!/usr/bin/env python3

# by TheTechromancer

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

        # nested dictionary in format:
        # { target: { port: open_count ... } ... }
        self.targets = dict()
        for target in targets:
            self.targets[target]        = dict()

        # dictionary in format:
        # { port: open_count ... }
        self.open_ports                 = dict()

        # dictionary in format:
        # { ip_address(): Host() ... }
        self.hosts                      = dict()
        self.zmap_ping_targets          = set()
        self.eternal_blue_count         = 0
        self.host_discovery_finished    = False

        self.online_hosts_file          = str(work_dir / 'zmap_all_online_hosts.txt')

        self.update_config(bandwidth, work_dir, blacklist)
        self.load_scan_cache()


    def start(self):

        if self.zmap_ping_targets:

            #if not self.primary_zmap_started and not host_discovery_finished:
            self.primary_zmap_started = True

            zmap_command = ['zmap', '--blacklist-file={}'.format(self.blacklist), \
                '--bandwidth={}'.format(self.bandwidth), \
                '--probe-module=icmp_echoscan'] + [str(t) for t in self.zmap_ping_targets]

            print('\n[+] Running zmap:\n\t> {}\n'.format(' '.join(zmap_command)))

            try:
                self.primary_zmap_process = sp.Popen(zmap_command, stdout=sp.PIPE)
            except sp.CalledProcessError as e:
                sys.stderr.write('[!] Error launching zmap: {}\n'.format(str(e)))
                sys.exit(1)

            self.zmap_ping_targets.clear()


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


    def ips_sorted(self, hosts=None):

        ips_sorted = []

        if hosts is None:
            ips_sorted = list(self.hosts.keys())
        else:
            ips_sorted = [str(h) for h in hosts]

        ips_sorted.sort(key=lambda x: ipaddress.ip_address(x))
        return ips_sorted


    def hosts_sorted(self, hosts=None):

        hosts_sorted = []

        if hosts is None:
            hosts_sorted = list(self.hosts.values())
        else:
            hosts_sorted = [Host(h) for h in hosts]

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
                    try:
                        self.hosts[ip]['Vulnerable to EternalBlue'] = 'Yes'
                    except KeyError:
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
            print('\t{:<19}{:<10}'.format(str(subnet[0]), ' ({:,})'.format(subnet[1])))

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

        port = int(port)
        zmap_out_file = self.work_dir / 'zmap_port_{}.txt'.format(port)
        zmap_whitelist_file = self.work_dir / '.zmap_tmp_whitelist_port_{}.txt'.format(port)
        targets = [t[0] for t in self.targets.items() if port not in t[1]]

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

            zmap_command = ['zmap', '--blacklist-file={}'.format(self.blacklist), \
                '--whitelist-file={}'.format(str(zmap_whitelist_file)), \
                '--bandwidth={}'.format(self.bandwidth), \
                '--target-port={}'.format(port)]

            print('\n[+] Running zmap:\n\t> {}\n'.format(' '.join(zmap_command)))

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
                        print('[+] {:<23}{:<10}'.format('{}:{}'.format(str(ip), port), self.hosts[ip]['Hostname']))
                        f.write(str(ip) + '\n')
                        self.hosts[ip].open_ports.add(port)
                        open_port_count += 1
                        hosts_written = True

                if not hosts_written:
                    print('[!] No hosts found with port {} open'.format(port))
                    return

                if open_port_count > 0:
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

            for host in self.hosts_sorted(hosts):
                self._write_csv_line(csv_writer, host)

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

        #targets = [str(t).replace('/', '-') for t in self.targets]
        cached_targets = []

        try:
            for target_dir in next(os.walk(self.work_dir))[1]:

                try:
                    target_net = ipaddress.ip_network(target_dir.replace('-', '/'))
                except ValueError:
                    continue

                if any([target_net == t for t in self.targets]):

                    target_dir = self.work_dir / target_dir

                    try:
                        for cache_file in next(os.walk(target_dir))[2]:

                            if cache_file.endswith('.csv'):
                                online_count, open_ports = self.read_csv(target_dir / cache_file)

                                if online_count > 0:
                                    cached_targets.append(target_net)
                                    try:
                                        self.targets[target_net].update(open_ports)
                                    except KeyError:
                                        self.targets[target_net] = open_ports

                                    for port, open_count in open_ports.items():
                                        try:
                                            self.open_ports[port] += open_count
                                        except KeyError:
                                            self.open_ports[port] = open_count

                                    print('[+] Found cached data for {}'.format(str(target_net)))

                    except StopIteration:
                        continue

        except StopIteration:
            return

        for target in self.targets:
            if not target in cached_targets:
                self.zmap_ping_targets.add(target)




        '''
        with open(str(Path(target_dir) / cache_file), newline='') as f:

            if cache_file.startswith('zmap_ping'):
                
                csv_file = csv.DictReader(f, fieldnames=['IP Address', 'Hostname'])

            elif cache_file.endswith('.csv'):

                csv_file = csv.DictReader(f, fieldnames=['IP Address', 'Hostname'])
                # remove header
                next(csv_file)
                hosts = list(csv_file)

                if cache_file.startswith('tcp_port_'):
                    for host in hosts:

                        try:
                            ip, hostname = (host['IP Address'], host['Hostname'])
                            port = int(cache_file.split('.')[0].split('tcp_port_')[1])
                        except ValueError:
                            continue

                        try:
                            self.hosts[ip].open_ports.add(port)
                        except KeyError:
                            self.hosts[ip] = Host(ip=ip, hostname=hostname)
                            self.hosts[ip].open_ports.add(port)
        '''



    def read_csv(self, csv_file):
        '''
        takes name of CSV file to read
        returns number of hosts therein
        '''

        hosts_in_csv = dict()
        open_ports = dict()

        # default CSV output
        if csv_file is None:
            csv_file = self.work_dir / 'state.csv'

        with open(str(csv_file), newline='') as f:
            c = csv.DictReader(f)

            for line in c:

                try:
                    ip = ipaddress.ip_address(line['IP Address'])
                except ValueError:
                    continue

                host = Host(ip=ip, hostname=line['Hostname'])
                vulnerable_to_eb = line['Vulnerable to EternalBlue']
                if vulnerable_to_eb == 'Yes':
                    self.eternal_blue_count += 1
                host['Vulnerable to EternalBlue'] = vulnerable_to_eb

                for field in c.fieldnames:
                    if field.endswith('/TCP'):
                        port = int(field.split('/')[0])
                        if line[field] == 'Open':
                            host.open_ports.add(port)
                            try:
                                open_ports[port] += 1
                            except KeyError:
                                open_ports[port] = 1

                hosts_in_csv[ip] = host

        if len(hosts_in_csv) > 0:
            self.hosts.update(hosts_in_csv)

        return (len(hosts_in_csv), open_ports)




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
            ['{}/TCP'.format(port) for port in self.open_ports])
        csv_writer.writeheader()

        return (csv_writer, f)



    def _write_csv_line(self, csv_writer, host, ports=None):

        if ports is None:
            ports = self.open_ports

        if not type(host) == Host:
            # try:
            #     host = self.hosts[ipaddress.ip_address(host['IP Address'])]
            # except TypeError:
            try:
                host = self.hosts[ipaddress.ip_address(host)]
            except ValueError:
                return


        open_ports = dict()
        for port in ports:
            if port in host.open_ports:
                open_ports['{}/TCP'.format(port)] = 'Open'
            else:
                open_ports['{}/TCP'.format(port)] = 'Closed'

        host.update(open_ports)
        csv_writer.writerow(host)



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

        with open(self.online_hosts_file, 'w') as f:

            for host in self.hosts.values():
                f.write(host['IP Address'] + '\n')
                yield host

            if self.zmap_ping_targets:

                self.primary_zmap_started = True

                self.start()
                sleep(1)
                for line in io.TextIOWrapper(self.primary_zmap_process.stdout, encoding='utf-8'):
                    try:
                        ip = ipaddress.ip_address(line.strip())
                    except ValueError:
                        continue
                    host = Host(ip, resolve=True)
                    print('[+] {:<17}{:<10} '.format(str(ip), host['Hostname']))
                    self.hosts[ip] = host
                    f.write(str(ip) + '\n')
                    yield host

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
            # print('[+] Parsing Nmap results')

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




class Host(dict):

    def __init__(self, ip, hostname=None, resolve=False):

        super().__init__()

        self['IP Address'] = str(ip)

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



    def __str__(self):

        return '{:<16}{}'.format(self['IP Address'], self['Hostname'])



def main(options):

    if os.geteuid() != 0:
        sys.stderr.write('[!] Must be root\n')
        sys.exit(2)

    # resolve symlinks
    options.work_dir = options.work_dir.resolve()

    cache_dir = options.work_dir / 'cache'
    nmap_dir = cache_dir / 'nmap'

    # if starting fresh rename working directory to ".bak"
    if options.start_fresh:
        backup_cache_dir = Path(str(cache_dir) + '_{date:%Y-%m-%d_%H:%M:%S}.bak'.format( date=datetime.now() ))
        try:
            old_dir = str(cache_dir)
            cache_dir.rename(backup_cache_dir)
            print('[+] Backed up {} to {}'.format(old_dir, str(backup_cache_dir)))
        except FileNotFoundError:
            pass

    # create directories if they don't exist
    nmap_dir.mkdir(mode=0o755, parents=True, exist_ok=True)


    if options.csv_file is None:
        options.csv_file = options.work_dir / 'asset_inventory.csv'


    # try to load "Zmap" object from pickled state
    '''
    saved_state = str(options.work_dir / '.state')
    try:

        with open(saved_state, 'rb') as f:
            z = pickle.load(f)
            print('[+] Loaded saved state from {}'.format(saved_state))
            z.update_config(options.bandwidth, work_dir=options.work_dir, blacklist=options.blacklist)

    except (FileNotFoundError, EOFError):
        print('[+] No state found at {}, starting fresh'.format(saved_state))
        z = Zmap(options.targets, options.bandwidth, work_dir=options.work_dir / 'cache', blacklist=options.blacklist)
    '''

    z = Zmap(options.targets, options.bandwidth, work_dir=cache_dir, blacklist=options.blacklist)

    # load cached scan data
    # z.load_scan_cache()

    # check for EternalBlue
    if options.check_eternal_blue:
        z.check_eternal_blue()

    # scan additional ports if requested
    # only alive hosts are scanned
    if options.ports is not None:
        for port in options.ports:
            z.scan_online_hosts(port)

    # write CSV file
    z.write_csv(csv_file=options.csv_file)

    # print summary
    z.report(netmask=options.netmask)
    if options.check_eternal_blue and z.eternal_blue_count <= 0:
        print('[+] No systems found vulnerable to EternalBlue')
        print('')

    # calculate deltas if requested
    if options.diff:
        stray_hosts = []
        stray_networks = []

        stray_networks = z.get_network_delta(options.diff, netmask=options.netmask)
        stray_networks_csv = './network_diff_{date:%Y-%m-%d_%H%M%S}.csv'.format( date=datetime.now())
        print('')
        print('[+] {:,} active network(s) not found in {}'.format(len(stray_networks), str(options.diff)))
        print('[+] Full report written to {}'.format(stray_networks_csv))
        print('=' * 60)

        with open(stray_networks_csv, 'w', newline='') as f:
            csv_file = csv.DictWriter(f, fieldnames=['Network', 'Host Count'])
            csv_file.writeheader()

            max_display_count = 20
            for network in stray_networks:
                csv_file.writerow({'Network': str(network[0]), 'Host Count': str(network[1])})
                #print('\t{:<16}{}'.format(str(network[0]), network[1]))
                print('\t{:<19}{:<10}'.format(str(network[0]), ' ({:,})'.format(network[1])))
                max_display_count -= 1
                if max_display_count <= 0:
                    print('\t...')
                    break

        stray_hosts = z.get_host_delta(options.diff)
        stray_hosts_csv = './host_diff_{date:%Y-%m-%d_%H%M%S}.csv'.format( date=datetime.now())
        print('')
        print('[+] {:,} alive host(s) not found in {}'.format(len(stray_hosts), str(options.diff)))
        print('[+] Full report written to {}'.format(stray_hosts_csv))
        print('=' * 60)

        max_display_count = 20
        for host in stray_hosts:
            print('\t{}'.format(str(host)))
            max_display_count -= 1
            if max_display_count <= 0:
                print('\t...')
                break

        z.write_csv(csv_file=stray_hosts_csv, hosts=stray_hosts)

        '''
        with open(stray_hosts_csv, 'w', newline='') as f:
            csv_file = csv.DictWriter(f, fieldnames=['IP Address', 'Hostname'])
            csv_file.writeheader()
            for host in stray_hosts:
                host = z.hosts[str(host)]
                csv_file.writerow({'IP Address': host['IP Address'], 'Hostname': host['Hostname']})
                print('\t{}'.format(str(host)))
        '''

        # if more than 5 percent of hosts are strays, or you have more than one stray network
        if len(stray_hosts)/len(z.hosts) > .05 or len(stray_networks) > 1:
            print('')
            print(' "Your asset management is bad and you should feel bad"')
            print('\n')

    print('[+] CSV file written to {}'.format(options.csv_file))

    z.stop()
    z.dump_scan_cache()
    # pickle Zmap object to save state
    # with open(saved_state, 'wb') as f:
    #     print('[+] Saving state to {}'.format(str(saved_state)))
    #     pickle.dump(z, f)




def str_to_network(s):
    '''
    takes either CIDR or range notation as string
    generates ip_network objects
    '''

    try:
        if '-' in s:
            start, end = s.split('-')[:2]
            for i in ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)):
                yield i
        else:
            yield ipaddress.ip_network(s, strict=False)

    except ValueError:
        raise ValueError('Cannot create host/network from "{}"'.format(str(s)))


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

    default_bandwidth = '1M'
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
    parser.add_argument('--work-dir', type=Path, default=default_work_dir,      help='custom working directory', metavar='DIR')
    parser.add_argument('-d', '--diff',             type=Path,                  help='show differences between scan results and IPs/networks from file', metavar='FILE')
    parser.add_argument('-n', '--netmask', type=int, default=default_cidr_mask, help='summarize networks with this CIDR mask (default {})'.format(default_cidr_mask))

    try:

        options = parser.parse_args()
        options.targets = parse_target_args(options.targets)
        if not options.targets:
            sys.stderr.write('\n[!] No valid targets\n')
            sys.exit(1)

        assert 0 <= options.netmask <=32, "Invalid netmask"

        
        #scan_uid = '_'.join([str(t).replace('/', '-') for t in options.targets])
        #if options.work_dir is None:
        #    # unique identifier based on scan targets
        #    options.work_dir = default_work_dir



        main(options)


    except (argparse.ArgumentError, AssertionError) as e:
        sys.stderr.write('\n[!] {}\n'.format(str(e)))
        sys.exit(2)

    except KeyboardInterrupt:
        sys.stderr.write('\n[!] Interrupted\n')
        sys.exit(1)