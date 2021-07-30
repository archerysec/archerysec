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

import hashlib
import uuid
from datetime import datetime

from dashboard.views import trend_update
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from utility.email_notify import email_sch_notify

name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""
vuln_color = None


def updated_xml_parser(root, project_id, scan_id):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :param username:
    :return:
    """
    global host, name, severity, port, threat, creation_time, modification_time, description, family, cvss_base, cve
    for openvas in root.findall(".//result"):
        for r in openvas:
            if r.tag == "name":
                global name
                if r.text is None:
                    name = "NA"
                else:
                    name = r.text
            if r.tag == "host":
                global host
                if r.text is None:
                    host = "NA"
                else:
                    host = r.text
            if r.tag == "port":
                global port
                if r.text is None:
                    port = "NA"
                else:
                    port = r.text
            if r.tag == "threat":
                global threat
                if r.text is None:
                    threat = "NA"
                else:
                    threat = r.text
            if r.tag == "severity":
                global severity
                if r.text is None:
                    severity = "NA"
                else:
                    severity = r.text
            if r.tag == "description":
                global description
                if r.text is None:
                    description = "NA"
                else:
                    description = r.text
        date_time = datetime.now()
        vuln_id = uuid.uuid4()
        dup_data = name + host + severity + port
        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()
        match_dup = (
            NetworkScanResultsDb.objects.filter(vuln_duplicate=duplicate_hash)
            .values("vuln_duplicate")
            .distinct()
        )
        lenth_match = len(match_dup)
        vuln_color = ""
        if lenth_match == 0:
            duplicate_vuln = "No"
            false_p = NetworkScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash
            )
            fp_lenth_match = len(false_p)
            if fp_lenth_match == 1:
                false_positive = "Yes"
            else:
                false_positive = "No"
            if threat == "High":
                vuln_color = "danger"
            elif threat == "Medium":
                vuln_color = "warning"
            elif threat == "Low":
                vuln_color = "info"
            elif threat == "Log":
                vuln_color = "info"

            save_all = NetworkScanResultsDb(
                scan_id=scan_id,
                project_id=project_id,
                vuln_id=vuln_id,
                title=name,
                date_time=date_time,
                severity=threat,
                description=description,
                port=port,
                ip=host,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                severity_color=vuln_color,
                false_positive=false_positive,
                scanner="Openvas",
            )
            save_all.save()
        else:
            duplicate_vuln = "Yes"
            all_data_save = NetworkScanResultsDb(
                scan_id=scan_id,
                project_id=project_id,
                vuln_id=vuln_id,
                title=name,
                date_time=date_time,
                severity=threat,
                description=description,
                port=port,
                ip=host,
                false_positive="Duplicate",
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                severity_color=vuln_color,
                scanner="Openvas",
            )
            all_data_save.save()

        openvas_vul = NetworkScanResultsDb.objects.filter(scan_id=scan_id, ip=host)
        total_high = len(openvas_vul.filter(severity="High"))
        total_medium = len(openvas_vul.filter(severity="Medium"))
        total_low = len(openvas_vul.filter(severity="Low"))
        total_duplicate = len(openvas_vul.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low
        NetworkScanDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate,
        )
    trend_update()
    subject = "Archery Tool Scan Status - OpenVAS Report Uploaded"
    message = (
        "OpenVAS Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (scan_id, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


def get_hosts(root):
    hosts = []
    for openvas in root.findall(".//result"):
        for r in openvas:
            if r.tag == "host":
                global host
                if r.text is None:
                    host = "NA"
                else:
                    host = r.text
                    if host in hosts:
                        print("Already present " + host)
                    else:
                        hosts.append(host)
    return hosts
