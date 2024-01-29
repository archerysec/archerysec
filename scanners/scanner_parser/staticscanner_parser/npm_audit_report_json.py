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

from archeryapi.models import OrgAPIKey
from dashboard.views import trend_update
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from utility.email_notify import email_sch_notify

vul_col = ""


def npmaudit_report_json(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()

    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization
    global vul_col
    for vuln in data["advisories"]:
        title = data["advisories"][vuln]["title"]
        found_by = data["advisories"][vuln]["found_by"]
        reported_by = data["advisories"][vuln]["reported_by"]
        module_name = data["advisories"][vuln]["module_name"]
        cves = data["advisories"][vuln]["cves"]
        vulnerable_versions = data["advisories"][vuln]["vulnerable_versions"]
        patched_versions = data["advisories"][vuln]["patched_versions"]
        overview = data["advisories"][vuln]["overview"]
        recommendation = data["advisories"][vuln]["recommendation"]
        references = data["advisories"][vuln]["references"]
        access = data["advisories"][vuln]["access"]
        severity = data["advisories"][vuln]["severity"]
        cwe = data["advisories"][vuln]["cwe"]
        # metadata = data["advisories"][vuln]["metadata"]
        url = data["advisories"][vuln]["url"]

        findings = data["advisories"][vuln]["findings"]
        vuln_versions = {}
        for find in findings:
            vuln_versions[find["version"]] = [find["paths"]]

        if not title:
            title = "not found"
        if not found_by:
            found_by = "not found"
        if not reported_by:
            reported_by = "not found"
        if not module_name:
            module_name = "not found"
        if not cves:
            cves = "not found"
        if not vulnerable_versions:
            vulnerable_versions = "not found"
        if not patched_versions:
            patched_versions = "not found"
        if not recommendation:
            recommendation = "not found"
        if not overview:
            overview = "not found"
        if not references:
            references = "not found"
        if not access:
            access = "not found"
        if not severity:
            severity = "not found"
        if not cwe:
            cwe = "not found"
        if not url:
            url = "not found"

        if severity == "critical":
            severity = "Critical"
            vul_col = "critical"

        if severity == "high":
            severity = "High"
            vul_col = "danger"

        elif severity == "moderate":
            severity = "Medium"
            vul_col = "warning"

        elif severity == "low":
            severity = "Low"
            vul_col = "info"

        elif severity == "info":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(title) + str(severity) + str(module_name)

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
                date_time=date_time,
                scan_id=scan_id,
                project_id=project_id,
                severity_color=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                title=title,
                description=str(overview)
                + "\n\n"
                + str(vuln_versions)
                + "\n\n"
                + str(reported_by)
                + "\n\n"
                + str(module_name)
                + "\n\n"
                + str(cves)
                + "\n\n"
                + str(vuln_versions)
                + "\n\n"
                + str(patched_versions),
                solution=recommendation,
                references=references,
                severity=severity,
                scanner="Npmaudit",
                organization=organization,
            )
            save_all.save()

        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                date_time=date_time,
                scan_id=scan_id,
                project_id=project_id,
                severity_color=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive="Duplicate",
                title=title,
                description=str(overview)
                + "\n\n"
                + str(vuln_versions)
                + "\n\n"
                + str(reported_by)
                + "\n\n"
                + str(module_name)
                + "\n\n"
                + str(cves)
                + "\n\n"
                + str(vuln_versions)
                + "\n\n"
                + str(patched_versions),
                solution=recommendation,
                references=references,
                severity=severity,
                scanner="Npmaudit",
                organization=organization,
            )
            save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", organization=organization
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes", organization=organization
    )

    total_vul = len(all_findbugs_data)
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
        scanner="Npmaudit",
        organization=organization,
    )
    trend_update()
    subject = "Archery Tool Scan Status - Npmaudit Report Uploaded"
    message = (
        "Npmaudit Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("npm-audit", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "npmaudit": {
        "displayName": "npm-audit Scanner",
        "dbtype": "StaticScans",
        "dbname": "Npmaudit",
        "type": "JSON",
        "parserFunction": npmaudit_report_json,
        "icon": "/static/tools/npmaudit.png",
    }
}
