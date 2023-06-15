#!/usr/bin/env python
# Collect DNS Zone data from CloudFlare
# (c) 2023 Carsten Strotmann, sys4 AG

import CloudFlare
import redis
import configparser
from datetime import date, datetime, timedelta

configFilePath="dns-report.cfg"

def printd(*str):
    global debug
    if debug:
        print(str)

def main():
    global debug
    configParser = configparser.ConfigParser()
    configParser.read(configFilePath)
    debug = configParser['global'].getboolean('debug','no')
    printd("Debugging is enabled.")
    authtoken = configParser['dns-collect'].get('token','')
    printd("Using Auth-Token: ", authtoken)
    redis_expire = configParser['dns-collect'].get('redis_expire','5160000')
    printd("REDIS expire time is: ", redis_expire)
    ignorelist = configParser['dns-collect'].get('ignorelist','[]')
    printd("Ignorelist is: ", ignorelist)

    cf = CloudFlare.CloudFlare(token=authtoken)

    redisdb = redis.Redis(db=0)
    timestamp = date.today().isoformat()
    ts_until = date.today().isoformat() + "T00:00:00Z"
    ts_since = (date.today() - timedelta(days=1)).isoformat() + "T00:00:00Z"
    printd(timestamp, ts_since, ts_until)

    redisdb.sadd("timestamps", timestamp)

    zones = cf.zones.get(params = {'per_page':1000})
    for zone in zones:
        zone_name = zone['name']
        zone_id = zone['id']
        redisdb.sadd(timestamp + "_zones", zone_id + ".." + zone_name)

        if (not zone_name in ignorelist):
            printd(zone_id, zone_name)
            report = cf.zones.dns_analytics.report(zone_id,params = {
                'dimensions': "queryName, queryType",
                'metrics': "queryCount",
                'since': ts_since,
                'until': ts_until }
                                                   )
            data = report['data']
            zmetrics = {} # zone metrics
            if (data is not None):
                for metrics in data:
                    domain_name = metrics['dimensions'][0]
                    domain_type = metrics['dimensions'][1]
                    metric = metrics['metrics'][0]
                    printd("\t",domain_name,domain_type,metric)
                    zmetrics[domain_name + ".." + domain_type] = metric
                if (len(zmetrics) > 0):
                    print("Storing into REDIS:", timestamp + "_" + zone_name + "_metrics")
                    redisdb.hset(timestamp + "_" + zone_name + "_metrics", mapping=zmetrics)
                    redisdb.expire(timestamp + "_" + zone_name + "_metrics", redis_expire)

            try:
                dns_records = cf.zones.dns_records.get(zone_id)
            except CloudFlare.exceptions.CloudFlareAPIError as e:
                exit('/zones/dns_records.get %d %s - api call failed' % (e, e))
            zrecords = {} # zone records
            if dns_records:
                for dns_record in dns_records:
                    r_name = dns_record['name']
                    r_type = dns_record['type']
                    r_data = dns_record['content']
                    r_id = dns_record['id']
                    zrecords[r_id] = r_name + ".." + r_type + ".." + r_data
                    printd('\t', r_id, r_name, r_type, r_data)

                if (len(zrecords) > 0):
                    print("Storing into REDIS:", timestamp + "_" + zone_name + "_records")
                    redisdb.hset(timestamp + "_" + zone_name + "_records", mapping=zrecords)
                    redisdb.expire(timestamp + "_" + zone_name + "_records", redis_expire)

    exit(0)
if __name__ == '__main__':
    main()
