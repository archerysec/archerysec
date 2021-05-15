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
import json
import uuid
from datetime import datetime

from dashboard.views import trend_update
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify

vul_col = ""
Target = ""
VulnerabilityID = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
Severity = ""
References = ""
false_positive = ""


def twistlock_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """

    """
    {
    "results": [
        {
            "id": "sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "distro": "Debian GNU/Linux 9 (stretch)",
            "compliances": [
                {
                    "title": "Sensitive information provided in environment variables",
                    "severity": "high",
                    "cause": "The environment variables DD_CELERY_BROKER_PASSWORD,DD_DATABASE_PASSWORD,DD_SECRET_KEY contain sensitive data"
                }
            ],
            "complianceDistribution": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "total": 1
            },
            "vulnerabilities": [
                {
                    "id": "CVE-2013-7459",
                    "cvss": 9.8,
                    "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "description": "Heap-based buffer overflow in the ALGnew function in block_templace.c in Python Cryptography Toolkit (aka pycrypto) allows remote attackers to execute arbitrary code as demonstrated by a crafted iv parameter to cryptmsg.py.",
                    "severity": "critical",
                    "packageName": "pycrypto",
                    "packageVersion": "2.6.1",
                    "link": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2013-7459",
                    "riskFactors": {
                        "Attack complexity: low": {},
                        "Attack vector: network": {},
                        "Critical severity": {},
                        "Remote execution": {}
                    }
                }
            ],
            "vulnerabilityDistribution": {
                "critical": 1,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 1
            }
        }
    ]
    }
    """
    global false_positive
    date_time = datetime.now()
    vul_col = ""

    # Parser for above json data

    vuln = data["results"][0]["vulnerabilities"]

    for vuln_data in vuln:
        try:
            name = vuln_data["id"]
        except Exception as e:
            name = "Not Found"

        try:
            cvss = vuln_data["cvss"]
        except Exception as e:
            cvss = "Not Found"

        try:
            vector = vuln_data["vector"]
        except Exception as e:
            vector = "Not Found"

        try:
            description = vuln_data["description"]
        except Exception as e:
            description = "Not Found"

        try:
            severity = vuln_data["severity"]
            if severity == "critical":
                severity = "High"
        except Exception as e:
            severity = "Not Found"

        try:
            packageName = vuln_data["packageName"]
        except Exception as e:
            packageName = "Not Found"

        try:
            packageVersion = vuln_data["packageVersion"]
        except Exception as e:
            packageVersion = "Not Found"

        try:
            link = vuln_data["link"]
        except Exception as e:
            link = "Not Found"

        if severity == "Critical":
            severity = "High"
            vul_col = "danger"

        if severity == "High":
            vul_col = "danger"

        elif severity == "Medium":
            vul_col = "warning"

        elif severity == "Low":
            vul_col = "info"

        elif severity == "Unknown":
            severity = "Low"
            vul_col = "info"

        elif severity == "Everything else":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(name) + str(severity) + str(packageName)

        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = StaticScanResultsDb.objects.filter(
            username=username, dup_hash=duplicate_hash
        ).values("dup_hash")
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = StaticScanResultsDb.objects.filter(
                username=username, false_positive_hash=duplicate_hash
            )
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = "Yes"
            else:
                false_positive = "No"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                username=username,
                name=name,
                cvss=cvss,
                description=description,
                Severity=severity,
                packageName=packageName,
                packageVersion=packageVersion,
                link=link,
            )
            save_all.save()
        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive="Duplicate",
                username=username,
                name=name,
                cvss=cvss,
                description=description,
                Severity=severity,
                packageName=packageName,
                packageVersion=packageVersion,
                link=link,
            )
            save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, false_positive="No", vuln_duplicate="No"
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(Severity="High"))
    total_medium = len(all_findbugs_data.filter(Severity="Medium"))
    total_low = len(all_findbugs_data.filter(Severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        username=username,
        date_time=date_time,
        total_vul=total_vul,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
    )
    trend_update(username=username)
    subject = "Archery Tool Scan Status - twistlock Report Uploaded"
    message = (
        "twistlock Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (Target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
