#!/usr/bin/env python
# DNS Fetch additional records Module
# (c) 2023 Carsten Strotmann, sys4 AG

import sys
import redis
import configparser
import dns.resolver
from datetime import date, datetime, timedelta

configFilePath = r'dns-report.cfg'

debug = 0
verbose = 0

def printd(*string):
    global debug
    if debug:
        print(str(string))

def printv(*string):
    global verbose
    if verbose:
        print("V> " + "".join(map(str,string)))

def main():
    global debug, verbose
    configParser = configparser.ConfigParser()
    configParser.read(configFilePath)
    debug = configParser['global'].getboolean('debug','no')
    printd("Debugging is enabled.")
    verbose = configParser['global'].getboolean('verbose','no')
    printd("Debugging is enabled.")
    resolver = configParser['dns-fetch'].get('resolver','1.1.1.1')
    printd("Using resolver: ", resolver)
    redis_expire = configParser['dns-fetch'].get('redis_expire','5160000')
    printd("REDIS expire time is: ", redis_expire)

    redisdb = redis.Redis(db=0)
    timestamp = date.today().isoformat()
    zones = redisdb.smembers(timestamp + "_zones")
    for zone in zones:
        zone_name = zone.decode('utf-8').split("..")[1]

        print (zone_name)
        dnssec_info = {}
        size = 0
        try:
            dns_name = dns.name.from_text(zone_name)
            dns_query = dns.message.make_query(dns_name,dns.rdatatype.DNSKEY)
            dns_query.ednsflags = dns.flags.DO
            dns_query.want_dnssec = True
            answers = dns.query.udp_with_fallback(dns_query, resolver)
            size = len(answers[0].to_wire())
        except dns.resolver.NoAnswer as e:
            printd("Domain " + zone_name + " does not contain DNSKEY records (NODATA)")
            size = 0
        except dns.resolver.NXDOMAIN as e:
            printd("Domain " + zone_name + " does not exists (NXDOMAIN)")
            size = 0

        dnssec_info['DNSKEY_RRSET_SIZE'] = size

        print("Storing into REDIS:", timestamp + "_" + zone_name + "_DNSSEC")
        redisdb.hset(timestamp + "_" + zone_name + "_DNSSEC", mapping=dnssec_info)
        redisdb.expire(timestamp + "_" + zone_name + "_DNSSEC", redis_expire)

    exit(0)

if __name__ == '__main__':
    main()
