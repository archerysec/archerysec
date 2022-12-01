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


def prisma_cloud_report_csv(data, project_id, scan_id):
    cloud_account_id = "na"
    vul_col = "na"
    date_time = datetime.now()
    for vuln in data:
        policy_name = vuln["Policy Name"]
        policy_type = vuln["Policy Type"]
        resource_name = vuln["Resource Name"]
        cloud_type = vuln["Cloud Type"]
        cloud_account_name = vuln["Cloud Account Name"]
        region = vuln["Region"]
        recommendation = vuln["Recommendation"]
        alert_status = vuln["Alert Status"]
        alert_time = vuln["Alert Time"]
        resource_id = vuln["Resource ID"]
        cloud_account_id = vuln["Cloud Account Id"]
        description = vuln["Description"]
        severity = vuln["Policy Severity"]

        if severity == "critical":
            severity = "Critical"
            vul_col = "critical"

        elif severity == "high":
            severity = "High"
            vul_col = "danger"

        elif severity == "medium":
            severity = "Medium"
            vul_col = "warning"

        elif severity == "low":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(policy_name) + str(severity) + str(cloud_account_id) + str(resource_id)

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
                title=policy_name,
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
                            + str(policy_type)
                            + "\n\n"
                            + str(cloud_account_name)
                            + "\n\n"
                            + str(region)
                            + "\n\n"
                            + str(alert_time)
                            + "\n\n"
                            + str(alert_status),
                references='NA',
                scanner="Prismacloud",
            )
            save_all.save()

        else:
            duplicate_vuln = "Yes"
            save_all = CloudScansResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                title=policy_name,
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
                            + str(policy_type)
                            + "\n\n"
                            + str(cloud_account_name)
                            + "\n\n"
                            + str(region)
                            + "\n\n"
                            + str(alert_time)
                            + "\n\n"
                            + str(alert_status),
                references='NA',
                scanner="Prismacloud",
            )
            save_all.save()
    all_prismacloud_data = CloudScansResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No"
    )

    duplicate_count = CloudScansResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_prismacloud_data)
    total_critical = len(all_prismacloud_data.filter(severity="Critical"))
    total_high = len(all_prismacloud_data.filter(severity="High"))
    total_medium = len(all_prismacloud_data.filter(severity="Medium"))
    total_low = len(all_prismacloud_data.filter(severity="Low"))
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
        scanner="Prismacloud",
    )
    trend_update()
    subject = "Archery Tool Scan Status - Prisma Cloud Report Uploaded"
    message = (
        "tfsec Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("Prisma Cloud", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


ParserHeaderDict = {
    "prisma_cspm": {
        "displayName": "Prisma CSPM",
        "dbtype": "CloudScans",
        "dbname": "Prismacloud",
        "type": "CSV",
        "parserFunction": prisma_cloud_report_csv,
        "icon": "/static/tools/prisma-cloud.png"
    }
}
