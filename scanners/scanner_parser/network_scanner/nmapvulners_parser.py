# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import datetime
import hashlib
import uuid

from dashboard.views import trend_update
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from utility.email_notify import email_sch_notify

agent = "NA"
description = "NA"
fname = "NA"
plugin_modification_date = "NA"
plugin_name = "NA"
plugin_publication_date = "NA"
plugin_type = "NA"
risk_factor = "NA"
script_version = "NA"
see_also = "NA"
solution = "NA"
synopsis = "NA"
plugin_output = "NA"
scan_ip = "NA"
pluginName = "NA"
pluginID = "NA"
protocol = "NA"
severity = "NA"
svc_name = "NA"
pluginFamily = "NA"
port = "NA"
ip = ""
false_positive = None
vuln_color = None
total_vul = "na"
total_high = "na"
total_medium = "na"
total_low = "na"
target = ""
report_name = ""


def xml_parser(root, project_id, scan_id):
    global agent, description, fname, plugin_modification_date, plugin_name, plugin_publication_date, plugin_type, risk_factor, script_version, solution, synopsis, plugin_output, see_also, scan_ip, pluginName, pluginID, protocol, severity, svc_name, pluginFamily, port, vuln_color, total_vul, total_high, total_medium, total_low, target, report_name

    try:
        date_time = datetime.datetime.fromtimestamp(int(root.get('start')))
    except Exception:
        date_time = datetime.datetime.now()

    target = root.find('./host/address').get('addr')

    for portsScanned in root.findall('./host/ports/port'):
        try:
            port = portsScanned.get('portid')
        except Exception:
            port = 'NA'
        try:
            fullDescription = portsScanned.find("./script[@id='vulners']").get('output')
        except Exception:
            description = 'NA'

        for vulnTable in portsScanned.findall("./script[@id='vulners']/table"):

            serviceName = vulnTable.get('key')

            for vulnData in vulnTable.findall("./table"):
                vuln_id = uuid.uuid4()

                try:
                    cvss = float(vulnData.find("./elem[@key='cvss']").text)
                except Exception:
                    cvss = 0.0

                if cvss >= 9.0:
                    vuln_color = "critical"
                    risk_factor = "Critical"
                elif cvss >= 7.0:
                    vuln_color = "danger"
                    risk_factor = "High"
                elif cvss >= 4.0:
                    vuln_color = "warning"
                    risk_factor = "Medium"
                elif cvss >= 0.1:
                    vuln_color = "info"
                    risk_factor = "Low"
                else:
                    risk_factor = "Low"
                    vuln_color = "info"

                try:
                    cveid = vulnData.find("./elem[@key='id']").text
                except Exception:
                    cveid = 'NA'

                splitDesc = fullDescription.splitlines()
                for lines in splitDesc:
                    if cveid in lines:
                        description = lines.strip()

                title = serviceName + ' | ' + cveid

                dup_data = target + serviceName + cveid + port
                duplicate_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                match_dup = (
                    NetworkScanResultsDb.objects.filter(dup_hash=duplicate_hash)
                    .values("dup_hash")
                    .distinct()
                )
                lenth_match = len(match_dup)

                if lenth_match == 0:
                    duplicate_vuln = "No"

                    global false_positive
                    false_p = NetworkScanResultsDb.objects.filter(
                        false_positive_hash=duplicate_hash
                    )
                    fp_lenth_match = len(false_p)
                    if fp_lenth_match == 1:
                        false_positive = "Yes"
                    else:
                        false_positive = "No"
                    if risk_factor == "None":
                        risk_factor = "Low"

                    all_data_save = NetworkScanResultsDb(
                        project_id=project_id,
                        scan_id=scan_id,
                        date_time=date_time,
                        title=title,
                        ip=target,
                        vuln_id=vuln_id,
                        description=description,
                        solution=solution,
                        severity=risk_factor,
                        port=port,
                        false_positive=false_positive,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        severity_color=vuln_color,
                        scanner="Nmapvulners",
                    )
                    all_data_save.save()

                else:
                    duplicate_vuln = "Yes"

                    all_data_save = NetworkScanResultsDb(
                        project_id=project_id,
                        scan_id=scan_id,
                        date_time=date_time,
                        title=pluginName,
                        ip=target,
                        vuln_id=vuln_id,
                        description=description,
                        solution=solution,
                        severity=risk_factor,
                        port=port,
                        false_positive="Duplicate",
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        severity_color=vuln_color,
                        scanner="Nmapvulners",
                    )
                    all_data_save.save()

    try:
        target_filter = NetworkScanResultsDb.objects.filter(
            ip=target,
            vuln_status="Open",
            vuln_duplicate="No",
        )

        duplicate_count = NetworkScanResultsDb.objects.filter(
            ip=target, vuln_duplicate="Yes"
        )

        target_total_vuln = len(target_filter)
        target_total_critical = len(target_filter.filter(severity="Critical"))
        target_total_high = len(target_filter.filter(severity="High"))
        target_total_medium = len(target_filter.filter(severity="Medium"))
        target_total_low = len(target_filter.filter(severity="Low"))
        target_total_duplicate = len(
            duplicate_count.filter(vuln_duplicate="Yes")
        )
        NetworkScanDb.objects.filter(ip=target).update(
            date_time=date_time,
            total_vul=target_total_vuln,
            critical_vul=target_total_critical,
            high_vul=target_total_high,
            medium_vul=target_total_medium,
            low_vul=target_total_low,
            total_dup=target_total_duplicate,
        )
    except Exception:
        print("Something went wrong while updating the vulnerability count")
        # pass

    trend_update()
    subject = "Archery Tool Scan Status - Nmap Vulners Report Uploaded"
    message = (
        "Nmap Vulners has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (scan_id, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


def get_host(root):
    target = root.find('./host/address').get('addr')
    return target


parser_header_dict = {
    "nmap_vulners": {
        "displayName": "Nmap Vulners Scanner",
        "dbtype": "NetworkScan",
        "dbname": "Nmapvulners",
        "type": "XML",
        "parserFunction": xml_parser,
        "icon": "/static/tools/nmap.png",
        "getHostFunction": get_host
    }
}
