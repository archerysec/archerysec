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

import csv
import hashlib
import uuid
from datetime import datetime

from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from dashboard.views import trend_update
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


def wiz_cloud_report_csv(data, project_id, scan_id, request):
    cloud_account_id = "na"
    vul_col = "na"
    date_time = datetime.now()
    for vuln in data:
        title = vuln["Title"]
        status = vuln["Status"]
        resource_original_json = vuln["Resource original JSON"]
        resource_name = vuln["Resource Name"]
        cloud_type = vuln["Resource Type"]
        cloud_account_name = vuln["Project Names"]
        region = vuln["Resource Region"]
        recommendation = "NA"
        created_at = vuln["Created At"]
        resource_id = vuln["Resource external ID"]
        cloud_account_id = vuln["Subscription ID"]
        description = "NA"
        severity = vuln["Severity"]

        if severity == "CRITICAL":
            severity = "Critical"
            vul_col = "critical"

        elif severity == "HIGH":
            severity = "High"
            vul_col = "danger"

        elif severity == "MEDIUM":
            severity = "Medium"
            vul_col = "warning"

        elif severity == "LOW":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(title) + str(severity) + str(cloud_account_id) + str(resource_id)

        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = CloudScansResultsDb.objects.filter(
            dup_hash=duplicate_hash, organization=request.user.organization
        ).values("dup_hash")
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = CloudScansResultsDb.objects.filter(
                false_positive_hash=duplicate_hash,
                organization=request.user.organization,
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
                + str(status)
                + "\n\n"
                + str(cloud_account_name)
                + "\n\n"
                + str(region)
                + "\n\n"
                + str(created_at)
                + "\n\n"
                + str(resource_original_json),
                references="NA",
                scanner="wiz",
                organization=request.user.organization,
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
                + str(status)
                + "\n\n"
                + str(cloud_account_name)
                + "\n\n"
                + str(region)
                + "\n\n"
                + str(created_at)
                + "\n\n"
                + str(resource_original_json),
                references="NA",
                scanner="wiz",
                organization=request.user.organization,
            )
            save_all.save()
    all_wizcloud_data = CloudScansResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", organization=request.user.organization
    )

    duplicate_count = CloudScansResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=request.user.organization
    )

    total_vul = len(all_wizcloud_data)
    total_critical = len(all_wizcloud_data.filter(severity="Critical"))
    total_high = len(all_wizcloud_data.filter(severity="High"))
    total_medium = len(all_wizcloud_data.filter(severity="Medium"))
    total_low = len(all_wizcloud_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    CloudScansDb.objects.filter(
        scan_id=scan_id, organization=request.user.organization
    ).update(
        cloudAccountId=cloud_account_id,
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="wiz",
    )
    trend_update()
    subject = "Archery Tool Scan Status - wiz Cloud Report Uploaded"
    message = (
        "Wiz Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("wiz Cloud", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "wiz": {
        "displayName": "Wiz",
        "dbtype": "CloudScans",
        "dbname": "wiz",
        "type": "CSV",
        "parserFunction": wiz_cloud_report_csv,
        "icon": "/static/tools/wiz.png",
    }
}
