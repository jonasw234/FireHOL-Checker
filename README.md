# FireHOL-Checker
Checks a list of IP addresses against the FireHOL database ([level 3](https://iplists.firehol.org/?ipset=firehol_level3) and [webserver](https://iplists.firehol.org/?ipset=firehol_webserver)).  
Locally caches the FireHOL lists for 12 hours ([average update frequency](https://iplists.firehol.org/) at the time of writing this script). 

Input list needs to be formated with one IPv4 address per line (no subnets/CIDR notation).

Usage examples:
```bash
> python firehol_checker.py ips_to_check.txt
✅ No suspicious IP addresses found.
```
```bash
> python firehol_checker.py ips_to_check.txt 
WARNING:🚨 Suspicious IP addresses:
2.58.240.15
```
