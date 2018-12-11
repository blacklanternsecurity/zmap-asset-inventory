# zmap-asset-inventory
Python script which takes internal asset inventory at scale using zmap.  Outputs to CSV.


## Features:
* Scans entire private IP space (by default)
    * Bandwidth, by default, is capped at 750kbps
* Automatic reverse-DNS lookups
* Ability to calculate delta between scan results and another list
    * Great for finding stray hosts
* Outputs to CSV
* Checks for EternalBlue
* Automatic caching of scan results
    * Run additional port scans without waiting for host discovery or DNS lookups 
    * Saves lots of time if scanning > thousands of hosts


## Workflow:

**zmap ping scan &rarr; zmap port scan(s) &rarr; EternalBlue check (optional) &rarr; CSV**


## Usage:
~~~
# ./zmap_asset_inventory.py --help
usage: Scan private IP ranges, output to CSV [-h] [-t STR [STR ...]]
                                             [--bandwidth STR]
                                             [--blacklist FILE] [-w CSV_FILE]
                                             [-f] [-p PORTS [PORTS ...]] [-e]
                                             [--work-dir WORK_DIR]

optional arguments:
  -h, --help            show this help message and exit
  -t STR [STR ...], --targets STR [STR ...]
                        target network(s) to scan
  --bandwidth STR       max egress bandwidth (default 750K)
  --blacklist FILE      a file containing hosts to exclude from scanning
  -w CSV_FILE, --csv-file CSV_FILE
                        output CSV file
  -f, --start-fresh     don't load results from previous scans
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        port-scan online hosts
  -e, --check-eternal-blue
                        scan for EternalBlue
  --work-dir WORK_DIR   custom working directory
~~~


## Example:
~~~
# ./zmap_asset_inventory.py -t 192.168.1.0/24 --check-eternal-blue
[+] No state found at /home/user/.asset_inventory/192.168.1.0-24/.state, starting fresh

[+] Running zmap:
    > zmap --blacklist-file=/home/user/.asset_inventory/192.168.1.0-24/.zmap_blacklist_tmp --bandwidth=750K --probe-module=icmp_echoscan 192.168.1.0/24

Dec 07 14:31:49.556 [INFO] zmap: output module: csv
Dec 07 14:31:49.556 [INFO] csv: no output file selected, will use stdout
 0:00 0%; send: 0 0 p/s (0 p/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
[+] 192.168.1.216    lt_14.evilcorp.local
[+] 192.168.1.198    lt_13.evilcorp.local
[+] 192.168.1.1      gateway.evilcorp.local
[+] 192.168.1.228    git.evilcorp.local
[+] 192.168.1.197    lt_15.evilcorp.local
[+] 192.168.1.196    lt_74.evilcorp.local
[+] 192.168.1.203    lt_12.evilcorp.local
[+] 192.168.1.214    lt_63.evilcorp.local
[+] 192.168.1.222    lt_24.evilcorp.local
[+] 192.168.1.204    lt_97.evilcorp.local
[+] 192.168.1.227    lt_10.evilcorp.local
[+] 192.168.1.218    lt_86.evilcorp.local
[+] 192.168.1.213    lt_84.evilcorp.local
[+] 192.168.1.212    lt_70.evilcorp.local
[+] 192.168.1.210    ldap.evilcorp.local
[+] 192.168.1.200    lt_66.evilcorp.local
[+] 192.168.1.220    lt_73.evilcorp.local
[+] 192.168.1.230    ras.evilcorp.local
 0:08 96% (1s left); send: 256 done (589 p/s avg); recv: 18 0 p/s (2 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 7.03%
Dec 07 14:31:58.621 [INFO] zmap: completed

[+] Scanning for EternalBlue
[+] Scanning 18 hosts on port 445

[+] Running zmap:
    > zmap --whitelist-file=/home/user/.asset_inventory/192.168.1.0-24/zmap_online_hosts.txt --bandwidth=750K --target-port=445

Dec 07 14:31:59.260 [INFO] zmap: output module: csv
Dec 07 14:31:59.260 [INFO] csv: no output file selected, will use stdout
 0:00 0%; send: 0 0 p/s (0 p/s avg); recv: 0 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 0.00%
[+] 192.168.1.216:445    lt_14.evilcorp.local
[+] 192.168.1.198:445    lt_13.evilcorp.local
[+] 192.168.1.197:445    lt_15.evilcorp.local
[+] 192.168.1.196:445    lt_74.evilcorp.local
[+] 192.168.1.203:445    lt_12.evilcorp.local
[+] 192.168.1.214:445    lt_63.evilcorp.local
[+] 192.168.1.222:445    lt_24.evilcorp.local
[+] 192.168.1.204:445    lt_97.evilcorp.local
[+] 192.168.1.227:445    lt_10.evilcorp.local
[+] 192.168.1.218:445    lt_86.evilcorp.local
[+] 192.168.1.213:445    lt_84.evilcorp.local
[+] 192.168.1.212:445    lt_70.evilcorp.local
[+] 192.168.1.210:445    ldap.evilcorp.local
[+] 192.168.1.200:445    lt_66.evilcorp.local
[+] 192.168.1.220:445    lt_73.evilcorp.local
 0:08 100% (1s left); send: 18 done (170 p/s avg); recv: 14 0 p/s (0 p/s avg); drops: 0 p/s (0 p/s avg); hitrate: 77.78%
Dec 07 14:32:08.328 [INFO] zmap: completed

[+] Running nmap:
    > nmap -p445 -T5 -n -Pn -v -sV --script=smb-vuln-ms17-010 -oA /home/user/.asset_inventory/192.168.1.0-24/nmap_output -iL /home/user/.asset_inventory/192.168.1.0-24/zmap_port_445.txt

[+] Finished Nmap scan
[+] Saved Nmap results to /home/user/.asset_inventory/192.168.1.0-24/nmap_output.*


[+] RESULTS:
==================================================
[+] Total Online Hosts: 18
[+] Summary of Subnets:
    192.168.X.X      (18)     

[+] Vulnerable to EternalBlue: 2
        192.168.1.227    lt_10.evilcorp.local 
        192.168.1.218    lt_86.evilcorp.local

[+] CSV file written to /home/user/.asset_inventory/192.168.1.0-24/asset_inventory.csv
~~~
