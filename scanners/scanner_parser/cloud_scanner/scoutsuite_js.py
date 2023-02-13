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
from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from utility.email_notify import email_sch_notify
import csv

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


def scoutsuite_cloud_report_js(data, project_id, scan_id):
    cloud_account_id = "na"
    recommendation = "na"
    vul_col = "na"
    date_time = datetime.now()
    cloud_account_id = data['account_id']
    cloud_account_name = data['account_id']
    cloud_type = data['provider_name']
    for key, value in data['services'].items():
        findings = data['services'][key]['findings']
        for finding_key, finding_value in findings.items():
            flagged = findings[finding_key]['flagged_items']
            if flagged != 0:
                vuln = findings[finding_key]
                title = vuln["description"]
                path = vuln["path"]
                resource_name = vuln["service"]
                region = "NA"
                if vuln["remediation"] is not None:
                    recommendation = vuln["remediation"]
                created_at = "NA"
                resource_id = vuln["items"]
                references = vuln["references"]
                description = vuln["rationale"]
                severity = vuln["level"]
                compliance = vuln["compliance"]

                if severity == "CRITICAL":
                    severity = "Critical"
                    vul_col = "critical"

                elif severity == "danger":
                    severity = "High"
                    vul_col = "danger"

                elif severity == "warning":
                    severity = "Medium"
                    vul_col = "warning"

                elif severity == "LOW":
                    severity = "Low"
                    vul_col = "info"

                vul_id = uuid.uuid4()

                dup_data = str(title) + str(severity) + str(cloud_account_id) + str(resource_id)

                duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

                match_dup = CloudScansResultsDb.objects.filter(dup_hash=duplicate_hash).values(
                    "dup_hash"
                )
                lenth_match = len(match_dup)

                if lenth_match == 0:
                    duplicate_vuln = "No"

                    false_p = CloudScansResultsDb.objects.filter(
                        false_positive_hash=duplicate_hash
                    )
                    fp_lenth_match = len(false_p)

                    if fp_lenth_match == 1:
                        false_positive = "Yes"
                    else:
                        false_positive = "No"

                    save_all = CloudScansResultsDb(
                        vuln_id=vul_id,
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        severity_color=vul_col,
                        title=title,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive=false_positive,
                        resourceName=resource_name,
                        resourceId=resource_id,
                        cloudType=cloud_type,
                        cloudAccountId=cloud_account_id,
                        solution=recommendation,
                        severity=severity,
                        description=str(description)
                                    + "\n\n"
                                    + str(path)
                                    + "\n\n"
                                    + str(cloud_account_name)
                                    + "\n\n"
                                    + str(region)
                                    + "\n\n"
                                    + str(created_at)
                                    + "\n\n"
                                    + str(compliance),
                        references=references,
                        scanner="scoutsuite",
                    )
                    save_all.save()

                else:
                    duplicate_vuln = "Yes"
                    save_all = CloudScansResultsDb(
                        vuln_id=vul_id,
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        title=title,
                        severity_color=vul_col,
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        false_positive="Duplicate",
                        resourceName=resource_name,
                        resourceId=resource_id,
                        cloudType=cloud_type,
                        cloudAccountId=cloud_account_id,
                        solution=recommendation,
                        severity=severity,
                        description=str(description)
                                    + "\n\n"
                                    + str(path)
                                    + "\n\n"
                                    + str(cloud_account_name)
                                    + "\n\n"
                                    + str(region)
                                    + "\n\n"
                                    + str(created_at)
                                    + "\n\n"
                                    + str(compliance),
                        references=references,
                        scanner="scoutsuite",
                    )
                    save_all.save()
    all_scoutsuitecloud_data = CloudScansResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No"
    )

    duplicate_count = CloudScansResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_scoutsuitecloud_data)
    total_critical = len(all_scoutsuitecloud_data.filter(severity="Critical"))
    total_high = len(all_scoutsuitecloud_data.filter(severity="High"))
    total_medium = len(all_scoutsuitecloud_data.filter(severity="Medium"))
    total_low = len(all_scoutsuitecloud_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    CloudScansDb.objects.filter(scan_id=scan_id).update(
        cloudAccountId=cloud_account_id,
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="scoutsuite",
    )
    trend_update()
    subject = "Archery Tool Scan Status - scoutsuite Cloud Report Uploaded"
    message = (
        "Scout Suite Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("scoutsuite Cloud", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "scoutsuite": {
        "displayName": "Scout Suite",
        "dbtype": "CloudScans",
        "dbname": "scoutsuite",
        "type": "JS",
        "parserFunction": scoutsuite_cloud_report_js,
        "icon": "/static/tools/scoutsuite.png"
    }
}
