#!/usr/bin/env python
# DNS Report Module
# (c) 2023 Carsten Strotmann, sys4 AG

import redis
import datetime
import sys
import getopt

debug = False
verbose = False
statistics = False
details = True

def printd(*string):
    if debug:
        print(str(string))

def printv(*string):
    if verbose:
        print("V> " + "".join(map(str,string)))

def printr(*string):
    print("".join(map(str,string)))

def usage():
    # TODO - Help text
    print("dns-report - Generate DNS report")

def main():
    global statistics
    reports = {}

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hsoeiwvdr:", ["help", "report="])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(err)
        usage()
        sys.exit(2)

    print_err  = False
    print_warn = False
    print_opt  = False
    print_info = False
    report_by_error = False
    report_by_warning = False
    report_by_optimization = False

    for o, a in opts:
        if o in ("-v"):
            verbose = True
        elif o in ("-d"):
            debug = True
        elif o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-s"):
            statistics = True
        elif o in ("-o"):
            print_opt = True
        elif o in ("-e"):
            print_err = True
        elif o in ("-i"):
            print_info = True
        elif o in ("-o"):
            print_opt = True
        elif o in ("-w"):
            print_warn = True
        elif o in ("-r", "--report"):
            if "warn" in a:
                report_by_warning = True
            if "err" in a:
                report_by_error = True
            if "opt" in a:
                report_by_optimization = True
        else:
            assert False, "unhandled option: " + o

    redisdb = redis.Redis(db=0)
    timestamps = redisdb.smembers("timestamps")
    printd (timestamps)

    # Global statistics counter
    num_alias_domains = 0
    num_arpa_domains = 0
    num_dnssec_domains = 0
    num_zones = 0
    num_https_records = 0
    num_microsoft_o365_txt = 0
    num_swisssign_txt = 0
    num_google_site_txt = 0
    num_facebook_site_txt = 0
    num_miro_site_txt = 0
    num_atlassian_site_txt = 0
    num_acme_challenge_txt = 0
    alias_domains = 0
    stat_optimization = 0
    stat_warning = 0
    stat_error = 0
    stat_info = 0

    for timestamp in timestamps:
        ts = timestamp.decode('utf-8')
        zones = redisdb.smembers(ts + "_zones")

        for zone in zones:
            report          = {}
            error_report    = {}
            warning_report  = {}
            optimize_report = {}

            num_zones += 1

            num_warning = 0
            num_error = 0
            num_optimize = 0
            num_info = 0

            report["is_alias_domain"] = False
            report["is_arpa_domain"] = False
            report["is_dnssec_enabled"] = False
            report["num_caa_records"] = 0
            report["num_https_queries"] = 0
            report["has_iodef_caa"] = False
            report["has_issue_caa"] = False
            report["has_issuewild_caa"] = False
            report["has_www_name"] = False
            report["has_dnskey_record"] = False
            report["num_dnskey_records"] = 0
            report["num_mx_records"] = 0
            report["has_https_record"] = False
            report["has_spf_data"] = False
            report["has_spf_record"] = False
            report["has_dkim_data"] = False
            report["has_dmarc_data"] = False
            report["has_swisssign_txt"] = False
            report["has_microsoft_o365_txt"] = False
            report["has_google_site_txt"] = False
            report["has_facebook_site_txt"] = False
            report["has_miro_site_txt"] = False
            report["has_atlassian_site_txt"] = False
            report["has_acme_challenge_txt"] = False
            report["has_cname_www"] = False
            report["warn_missing_www_caa_record"] = False
            report["warn_missing_swisssign_caa_record"] = False
            report["warn_has_mx_missing_spf"] = False
            report["warn_missing_dmarc"] = False
            report["warn_missing_dkim"] = False
            report["opt_www_missing_https"] = False

            zone_name = zone.decode('utf-8').split("..")[1]
            report["zone_name"] = zone_name

            printv("Retrieving from REDIS:", ts + "_" + zone_name + "_metrics")
            zmetrics = redisdb.hgetall(ts + "_" + zone_name + "_metrics")
            printv("Retrieving from REDIS:", ts + "_" + zone_name + "_DNSSEC")
            dnssec_info = redisdb.hgetall(ts + "_" + zone_name + "_DNSSEC")
            printd("DNSSEC-INFO:" + str(dnssec_info))
            for metric in zmetrics:
                metric_name = metric.decode("utf-8")
                printd (metric_name, int(zmetrics[metric]))

            key = str.encode(zone_name + "..HTTPS","UTF-8")
            if key in zmetrics:
                report["num_https_queries"] = int(zmetrics[key].decode("UTF-8"))

            printv("Retrieving from REDIS:", ts + "_" + zone_name + "_records")
            records = redisdb.hgetall(ts + "_" + zone_name + "_records")
            for r_id in records:
                r_value = records[r_id].decode('utf-8')
                r_name, r_type, r_data = r_value.split("..")
                printd (r_name, r_type, r_data)

                # Test for alias domain (CloudFlare specific)
                if (r_type == "CNAME") and (r_name == zone_name):
                    printv(zone_name + " is an alias domain")
                    report["is_alias_domain"] = True
                    num_alias_domains += 1

                if (r_name.find(".arpa") > -1):
                    printv(zone_name + " is an ARPA domain")
                    report["is_arpa_domain"] = True
                    num_arpa_domains += 1


                # Test for CAA records in domain
                if (r_type == "CAA"):
                    report["num_caa_records"] += 1
                    printv("CAA-Record for ", r_name)
                    if (r_data.find("issue") > -1):
                        report["has_issue_caa"] = True
                        printv("  Is an /issue/ type CAA record")
                    if (r_data.find("issuewild") > -1):
                        report["has_issuewild_caa"] = True
                        printv("  Is an /issuewild/ type CAA record")
                    if (r_data.find("iodef") > -1):
                        report["has_iodef_caa"] = True
                        printv("  Is an /iodef/ type CAA record")

                # Test for DNSSEC
                if (r_type == "DNSKEY"):
                    printv(zone_name + " has a DNSKEY record - is DNSSEC enabled")
                    report["num_dnskey_records"] += 1
                if report["num_dnskey_records"] > 0 or (int(dnssec_info[bytes('DNSKEY_RRSET_SIZE',"utf-8")]) > 0):
                    report["is_dnssec_enabled"] = True

                # Test for Webserver /www/ name
                if (r_type == "A") or (r_type == "AAAA"):
                    if (r_name.find("www") > -1):
                        printv(zone_name + " has a /www/ name at " + r_name)
                        report["has_www_name"] = True
                if (r_type == "HTTPS"):
                    printv("Zone has an HTTPS record")
                    report["has_https_record"] = True
                    num_https_records += 1
                if (r_type == "MX"):
                    printv("Zone has an MX record for " + r_name)
                    report["num_mx_records"] += 1
                if (r_type == "TXT"):
                    printd(r_data)
                    if (r_name.find("_acme-challenge") > -1):
                        printv(zone_name + " has ACME challenge authorization token")
                        report["has_acme_challenge_txt"] = True
                        num_acme_challenge_txt += 1

                    if (r_data.find("MS=ms") > -1):
                        printv(zone_name + " has Microsoft Office365 domain owner authorization token")
                        report["has_microsoft_o365_txt"] = True
                        num_microsoft_o365_txt += 1
                    if (r_data.lower().find("swisssign=") > -1) and (r_name == zone_name):
                        printv(zone_name + " has a SwissSign Auth-Token at " + r_name)
                        report["has_swisssign_txt"] = True
                        num_swisssign_txt += 1
                    if (r_data.lower().find("swisssign-check=") > -1) and (r_name == zone_name):
                        printv(zone_name + " has a SwissSign Auth-Token at " + r_name)
                        report["has_swisssign_txt"] = True
                        num_swisssign_txt += 1
                    if (r_data.lower().find("google-site-verification=") > -1):
                        printv(zone_name + " has a Google-Site-Verification Auth-Token at " + r_name)
                        report["has_google_site_txt"] = True
                        num_google_site_txt += 1
                    if (r_data.lower().find("facebook-domain-verification=") > -1):
                        printv(zone_name + " has a Facebook Domain Verification Auth-Token at " + r_name)
                        report["has_facebook_site_txt"] = True
                        num_facebook_site_txt += 1
                    if (r_data.lower().find("miro-verification=") > -1) and (r_name == zone_name):
                        printv(zone_name + " has a Miro Domain Control Auth-Token at " + r_name)
                        report["has_miro_site_txt"] = True
                        num_miro_site_txt += 1
                    if (r_data.lower().find("atlassian-domain-verification=") > -1) and (r_name == zone_name):
                        printv(zone_name + " has a Atlassian Domain Verification Auth-Token at " + r_name)
                        report["has_atlassian_site_txt"] = True
                        num_atlassian_site_txt += 1
                    if (r_data.lower().find("v=spf1") > -1) and (r_name == zone_name):
                        printv(zone_name + " has a TXT record with SPF data at " + r_name)
                        report["has_spf_data"] = True
                    if (r_data.lower().find("v=dkim") > -1):
                        printv(zone_name + " has a TXT record with DKIM data at " + r_name)
                        report["has_dkim_data"] = True
                    if (r_data.lower().find("v=dmarc1") > -1) and (r_name.find("_dmarc") == 0):
                        printv(zone_name + " has a TXT record with DMARC data at " + r_name)
                        report["has_dmarc_data"] = True

                if (r_type == "SPF"):
                    printv(zone_name + " has a (deprecated) SPF record at " + r_name)
                    report["has_spf_data"] = True
                    report["has_spf_record"] = True

            if report["has_www_name"] and report["num_caa_records"] == 0:
                report["warn_missing_www_caa_record"] = True
                num_warning += 1
            if report["has_https_record"] and report["num_caa_records"] == 0:
                report["warn_missing_www_caa_record"] = True
                num_warning += 1
            if report["has_swisssign_txt"] and report["num_caa_records"] == 0:
                report["warn_missing_swisssign_caa_record"] = True
                num_warning += 1
            if (not report["has_https_record"]) and (report["has_www_name"]) and report["num_https_queries"] > 0:
                report["opt_www_missing_https"] = True
                num_optimize += 1
            if report["num_mx_records"] > 0 and report["has_spf_data"]:
                report["warn_has_mx_missing_spf"] = True
                num_warning += 1
            if report["has_spf_record"]:
                num_warning += 1
            if (report["has_spf_data"] or report["num_mx_records"] > 0 or report["has_dkim_data"]) and (not report["has_dmarc_data"]):
                report["warn_missing_dmarc"] = True
                num_warning += 1
            if (report["has_spf_data"] or report["num_mx_records"] > 0 or report["has_dmarc_data"]) and (not report["has_dkim_data"]):
                report["warn_missing_dkim"] = True
                num_warning += 1
            if report["has_microsoft_o365_txt"]:
                num_optimize += 1
            if report["has_google_site_txt"]:
                num_optimize += 1
            if report["has_facebook_site_txt"]:
                num_optimize += 1
            if report["has_miro_site_txt"]:
                num_optimize =+ 1
            if report["has_atlassian_site_txt"]:
                num_optimize += 1
            if report["has_swisssign_txt"]:
                num_optimize += 1
            if report["is_dnssec_enabled"]:
                num_dnssec_domains += 1
            if report["is_alias_domain"]:
                num_info += 1
            if report["is_arpa_domain"]:
                num_info += 1
            if report["is_dnssec_enabled"]:
                num_info += 1
            if report["has_acme_challenge_txt"]:
                num_info += 1
            report["num_error"] = num_error
            report["num_warning"] = num_warning
            report["num_optimize"] = num_optimize
            report["num_info"] = num_info

            stat_warning += num_warning
            stat_optimization += num_optimize
            stat_error += num_error
            stat_info += num_info

            reports[zone_name] = report

    if statistics:
        printr()
        printr("Global statistics:")
        printr("  Zonen:                          ", num_zones)
        printr("  Alias-Domains:                  ", num_alias_domains)
        printr("  ARPA-Domains:                   ", num_arpa_domains)
        printr("  DNSSEC-Domains:                 ", num_dnssec_domains)
        printr("  HTTPS-Records:                  ", num_https_records)
        printr()
        printr("  ACME Challenge token:           ", num_acme_challenge_txt)
        printr("  Atlassian Domain Verification:  ", num_atlassian_site_txt)
        printr("  Facebook Site Validation token: ", num_facebook_site_txt)
        printr("  Google Site Validation token:   ", num_google_site_txt)
        printr("  Microsoft O365 token:           ", num_microsoft_o365_txt)
        printr("  Miro Domain Control token:      ", num_miro_site_txt)
        printr("  Swisssign token:                ", num_swisssign_txt)
        printr()
        printr("  Errors:                         ", stat_error)
        printr("  Warnings:                       ", stat_warning)
        printr("  Optimizations:                  ", stat_optimization)

    if details:
        sorted_zones=sorted(reports)
        for zone_name in sorted_zones:
            report=reports[zone_name]
            printflag = 0
            if print_info:
                printflag += report["num_info"]
            if print_warn:
                printflag += report["num_warning"]
            if print_opt:
                printflag += report["num_optimize"]
            if print_err:
                printflag += report["num_error"]

            if printflag > 0:
                printr ()
                printr ("Report for zone: " +  zone_name)
                printr ("-" * (len(zone_name) + 17))

                if print_info:
                    if report["is_alias_domain"]:
                        printr("I0001: Info: Zone is an alias domain")
                    if report["is_arpa_domain"]:
                        printr("I0002: Info: Zone is an ARPA (reverse DNS resolution) domain")
                    if report["is_dnssec_enabled"]:
                        printr("I0003: Info: Zone is DNSSEC enabled")
                    if report["has_acme_challenge_txt"]:
                        printr("I0100: Info: Zone has ACME challenge token")
                if print_warn:
                    if report["warn_missing_www_caa_record"]:
                        printr("W1000: Warning: Zone has a /www/ name, but no CAA record")
                    if report["warn_missing_swisssign_caa_record"]:
                        printr("W1001: Warning: Zone has a SwissSign Token, but no CAA record")
                    if report["warn_has_mx_missing_spf"]:
                        printr("W1100: Warning: Zone has MX records but no SPF data")
                    if report["has_spf_record"]:
                        printr("W1101: Warning: Zone has deprecated SPF record - migrate to SPF TXT record")
                    if report["warn_missing_dmarc"]:
                        printr("W1102: Warning: Domain with mail usage is missing a DMARC entry")
                    if report["warn_missing_dkim"]:
                        printr("W1103: Warning: Domain with mail usage is missing a DKIM entry")
                if print_opt:
                    if report["opt_www_missing_https"]:
                        printr("O1000: Optimization: Zone has a /www/ name, but no HTTPS record (" +  str(report["num_https_queries"]) + " HTTPS queries/day)")
                    if report["has_microsoft_o365_txt"]:
                        printr("O1100: Optimization: Domain contains an Microsoft Office365 authorization token that can possibly removed")
                        printr("   See: https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider")
                    if report["has_google_site_txt"]:
                        printr("O1101: Optimization: A Google Site Verification Token has been detected")
                        printr("   To prevent large TXT record sets on the domain APEX, it is recommended to evaluate alternative Google Site Validation methods")
                        printr("   See: https://support.google.com/webmasters/answer/9008080")
                    if report["has_facebook_site_txt"]:
                        printr("O1102: Optimization: A Facebook Domain Verification Token has been detected")
                        printr("   To prevent large TXT record sets on the domain APEX, it is recommended to evaluate alternative Facebook Domain Validation methods")
                        printr("   Facebook Domain Verification TXT records can be removed after successful verification")
                        printr("   See: https://developers.facebook.com/docs/sharing/domain-verification")
                    if report["has_miro_site_txt"]:
                        printr("O1103: Optimization: A Miro Domain Control Token has been detected")
                        printr("   To prevent large TXT record sets on the domain APEX, consider to move Miro Domain Control to a subdomain")
                        printr("   See: https://help.miro.com/hc/en-us/articles/360034831793-Domain-control")
                    if report["has_atlassian_site_txt"]:
                        printr("O1104: Optimization: A Atlassian Domain Verification Token has been detected")
                        printr("   To prevent large TXT record sets on the domain APEX, consider to move to Atlassian HTTPS verification")
                        printr("   See: https://support.atlassian.com/user-management/docs/verify-a-domain-to-manage-accounts/")
                    if report["has_swisssign_txt"]:
                        printr("O1105: Optimization: A SwissSign x509 Certificate Domain validation token has been detected")
                        printr("   To prevent large TXT record sets on the domain APEX, it is recommended to evaluate migration to text-file validation")
                        printr("   at https://" + zone_name + "/.well-known/pki-validation/swisssign-check.txt")
                        printr("   See: https://www.swisssign.com/en/news/detail~newsID=5d91caee-8fc7-4af9-b63b-eadae419ff29~.html")

                if statistics:
                    printr("Zone statistics:")
                    printr("  Errors         :", report["num_error"])
                    printr("  Warnings       :", report["num_warning"])
                    printr("  Optimizations  :", report["num_optimize"])
                    printr("  Infos          :", report["num_info"])

    if report_by_error:
        print("Report by error")
        sorted_zones=sorted(reports)
        zones_error_count = {}
        for zone_name in sorted_zones:
            report=reports[zone_name]
            if report["num_error"] > 0:
                zones_error_count[zone_name]=report["num_error"]
        for zone in sorted(zones_error_count.items(), key=lambda item: item[1], reverse=True):
            print(zone[1])

    if report_by_warning:
        print("Report by warning")
        sorted_zones=sorted(reports)
        zones_warning_count = {}
        for zone_name in sorted_zones:
            report=reports[zone_name]
            if report["num_warning"] > 0:
                zones_warning_count[zone_name]=report["num_warning"]
        for zone in sorted(zones_warning_count.items(), key=lambda item: item[1], reverse=True):
            zone_name=zone[0]
            print()
            print(zone_name)
            printr ("-" * (len(zone_name)))
            print("Warnings: ", zone[1])
            report=reports[zone_name]
            if report["warn_missing_www_caa_record"]:
                printr("W1000: Warning: Zone has a /www/ name, but no CAA record")
            if report["warn_missing_swisssign_caa_record"]:
                printr("W1001: Warning: Zone has a SwissSign Token, but no CAA record")
            if report["warn_has_mx_missing_spf"]:
                printr("W1100: Warning: Zone has MX records but no SPF data")
            if report["has_spf_record"]:
                printr("W1101: Warning: Zone has deprecated SPF record - migrate to SPF TXT record")
            if report["warn_missing_dmarc"]:
                printr("W1102: Warning: Domain with mail usage is missing a DMARC entry")
            if report["warn_missing_dkim"]:
                printr("W1103: Warning: Domain with mail usage is missing a DKIM entry")

    if report_by_optimization:
        print("Report by optmization")
        sorted_zones=sorted(reports)
        zones_optimization_count = {}
        for zone_name in sorted_zones:
            report=reports[zone_name]
            if report["num_optimize"] > 0:
                zones_optimization_count[zone_name]=report["num_optimize"]
        for zone in sorted(zones_optimization_count.items(), key=lambda item: item[1], reverse=True):
            zone_name=zone[0]
            print()
            print(zone_name)
            printr ("-" * (len(zone_name)))
            print("Optimizations: ", zone[1])
            report=reports[zone_name]
            if report["opt_www_missing_https"]:
                printr("O1000: Optimization: Zone has a /www/ name, but no HTTPS record (" +  str(report["num_https_queries"]) + " HTTPS queries/day)")
            if report["has_microsoft_o365_txt"]:
                printr("O1100: Optimization: Domain contains an Microsoft Office365 authorization token that can possibly removed")
                printr("   See: https://learn.microsoft.com/en-us/microsoft-365/admin/get-help-with-domains/create-dns-records-at-any-dns-hosting-provider")
            if report["has_google_site_txt"]:
                printr("O1101: Optimization: A Google Site Verification Token has been detected")
                printr("   To prevent large TXT record sets on the domain APEX, it is recommended to evaluate alternative Google Site Validation methods")
                printr("   See: https://support.google.com/webmasters/answer/9008080")
            if report["has_facebook_site_txt"]:
                printr("O1102: Optimization: A Facebook Domain Verification Token has been detected")
                printr("   To prevent large TXT record sets on the domain APEX, it is recommended to evaluate alternative Facebook Domain Validation methods")
                printr("   Facebook Domain Verification TXT records can be removed after successful verification")
                printr("   See: https://developers.facebook.com/docs/sharing/domain-verification")
            if report["has_miro_site_txt"]:
                printr("O1103: Optimization: A Miro Domain Control Token has been detected")
                printr("   To prevent large TXT record sets on the domain APEX, consider to move Miro Domain Control to a subdomain")
                printr("   See: https://help.miro.com/hc/en-us/articles/360034831793-Domain-control")
            if report["has_atlassian_site_txt"]:
                printr("O1104: Optimization: A Atlassian Domain Verification Token has been detected")
                printr("   To prevent large TXT record sets on the domain APEX, consider to move to Atlassian HTTPS verification")
                printr("   See: https://support.atlassian.com/user-management/docs/verify-a-domain-to-manage-accounts/")
            if report["has_swisssign_txt"]:
                printr("O1105: Optimization: A SwissSign x509 Certificate Domain validation token has been detected")
                printr("   To prevent large TXT record sets on the domain APEX, it is recommended to evaluate migration to text-file validation")
                printr("   at https://" + zone_name + "/.well-known/pki-validation/swisssign-check.txt")
                printr("   See: https://www.swisssign.com/en/news/detail~newsID=5d91caee-8fc7-4af9-b63b-eadae419ff29~.html")

    exit(0)

if __name__ == '__main__':
    main()
