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

from archeryapi.models import OrgAPIKey
from dashboard.views import trend_update
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify

vul_col = ""
severity = ""


def grype_report_json(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    global vul_col, severity
    matches = data["matches"]

    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization
    for vuln in matches:
        # # for key, value in vuln.items():
        # #     print(key, value)
        # print(vuln['matchDetails'][0]['searchedBy']['package']['version'])
        packagename = vuln["matchDetails"][0]["searchedBy"]["package"]["name"]
        packageversion = vuln["matchDetails"][0]["searchedBy"]["package"]["version"]
        package = packagename + " " + packageversion

        title = vuln["vulnerability"]["id"]
        dataSource = vuln["vulnerability"]["dataSource"]
        # namespace =
        vuln["vulnerability"]["namespace"]
        severity = vuln["vulnerability"]["severity"]
        urls = vuln["vulnerability"]["urls"]
        try:
            description = vuln["vulnerability"]["description"]
        except Exception:
            description = "NA"
        fix = vuln["vulnerability"]["fix"]["state"]
        fix_version = vuln["vulnerability"]["fix"]["versions"]
        advisories = vuln["vulnerability"]["advisories"]

        if severity == "Critical":
            vul_col = "critical"

        elif severity == "High":
            vul_col = "danger"

        elif severity == "Medium":
            vul_col = "warning"

        elif severity == "Low":
            vul_col = "info"

        else:
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(title) + str(severity) + str(package)

        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = StaticScanResultsDb.objects.filter(
            dup_hash=duplicate_hash, organization=organization
        ).values("dup_hash")
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = StaticScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash,
                organization=organization,
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
                severity_color=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                title=title,
                fileName=str(package),
                severity=severity,
                filePath=str(package),
                solution=str(fix) + " " + str(fix_version),
                description=str(description)
                + "\n\n"
                + str(urls)
                + "\n\n"
                + str(fix)
                + "\n\n"
                + str(advisories)
                + "\n\n"
                + str(dataSource),
                scanner="grype_scan",
                organization=organization,
            )
            save_all.save()

        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                severity_color=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive="Duplicate",
                title=title,
                fileName=package,
                severity=severity,
                filePath=package,
                solution=str(fix) + " " + str(fix_version),
                description=str(description)
                + "\n\n"
                + str(urls)
                + "\n\n"
                + str(fix)
                + "\n\n"
                + str(advisories)
                + "\n\n"
                + str(dataSource),
                scanner="grype_scan",
                organization=organization,
            )
            save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", organization=organization
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=organization
    )

    total_vul = len(
        all_findbugs_data.filter(severity__in=["Critical", "High", "Medium", "Low"])
    )
    total_critical = len(all_findbugs_data.filter(severity="Critical"))
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        total_vul=total_vul,
        date_time=date_time,
        critical_vul=total_critical,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="grype_scan",
        organization=organization,
    )
    trend_update()
    subject = "Archery Tool Scan Status - grype Report Uploaded"
    message = (
        "Nodejsscan Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("Nodejsscan", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "grype": {
        "displayName": "grype Scanner",
        "dbtype": "StaticScans",
        "dbname": "grype_scan",
        "type": "JSON",
        "parserFunction": grype_report_json,
        "icon": "/static/tools/grype.png",
    }
}
