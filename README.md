# WRA (Whois Requests Automation)

WRA is srcipt to make WHOIS requests. It picks up the most interesting items such as: inetnum, route, origin, and others.

Also you can choose the different output formats (json, txt at the moment).

## Examples:

### Check a single domain

``` cmd
$ ./whopy.py -d example.com
domain: example.com
ip: 93.184.216.34
inetnum: 93.184.216.0 - 93.184.216.255
netname: edgecast-netblk-03
country: eu
```

### Check list of domains and output result in json format (You can write it to file with '-o' option)

```cmd
$ ./whopy.py -D domains.txt -f json       
{"domain:": "example.com", "ip:": "93.184.216.34", "inetnum:": "93.184.216.0 - 93.184.216.255", "netname:": "edgecast-netblk-03", "country:": "eu"}
{"domain:": "scanme.nmap.org", "ip:": "45.33.32.156", "netname:": "linode-us", "country:": "us", "netrange:": "45.33.0.0 - 45.33.127.255", "cidr:": "45.33.0.0/17", "originas:": "as3595, as21844, as6939, as8001", "organization:": "akamai technologies, inc. (akamai)"}
```