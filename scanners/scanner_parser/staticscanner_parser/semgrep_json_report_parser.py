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
from staticscanners.models import (StaticScanResultsDb,
                                   StaticScansDb)
from utility.email_notify import email_sch_notify

vul_col = ""
Target = ""
PkgName = ""
InstalledVersion = ""
FixedVersion = ""
Title = ""
Description = ""
Severity = ""
References = ""


def semgrep_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    vul_col = ""

    vuln = data["results"]

    for vuln_data in vuln:
        try:
            check_id = vuln_data["check_id"]
        except Exception as e:
            check_id = "Not Found"

        try:
            path = vuln_data["path"]
        except Exception as e:
            path = "Not Found"

        try:
            start = vuln_data["start"]
        except Exception as e:
            start = "Not Found"

        try:
            end = vuln_data["end"]
        except Exception as e:
            end = "Not Found"

        try:
            message = vuln_data["extra"]["message"]
        except Exception as e:
            message = "Not Found"

        try:
            metavars = vuln_data["extra"]["metavars"]
        except Exception as e:
            metavars = "Not Found"

        try:
            metadata = vuln_data["extra"]["metadata"]
        except Exception as e:
            metadata = "Not Found"

        try:
            severity = vuln_data["extra"]["severity"]
        except Exception as e:
            severity = "Not Found"

        try:
            lines = vuln_data["extra"]["lines"]
        except Exception as e:
            lines = "Not Found"

        if severity == "ERROR":
            severity = "High"
            vul_col = "danger"

        elif severity == "WARNING":
            severity = "Medium"
            vul_col = "warning"

        elif severity == "INFORMATION":
            severity = "Low"
            vul_col = "info"

        vul_id = uuid.uuid4()

        dup_data = str(check_id) + str(severity) + str(path)

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
                title=check_id,
                severity_color=vul_col,
                vuln_status="Open",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,
                fileName=path,
                severity=severity,
                description=str(message) + '\n\n' + str(check_id) + '\n\n' + str(end) + '\n\n' + str(metavars) + '\n\n' + str(metadata) + '\n\n' + str(lines),
                username=username,
                scanner='Sempgrep'
            )
            save_all.save()

        else:
            duplicate_vuln = "Yes"

            save_all = StaticScanResultsDb(
                vuln_id=vul_id,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                title=check_id,
                severity_color=vul_col,
                vuln_status="Duplicate",
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                fileName=path,
                severity=severity,
                description=str(message) + '\n\n' + str(check_id) + '\n\n' + str(end) + '\n\n' + str(metavars) + '\n\n' + str(metadata) + '\n\n' + str(lines),
                username=username,
                scanner='Semgrep'
            )
            save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, false_positive="No"
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        username=username, scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(username=username, scan_id=scan_id).update(
        total_vul=total_vul,
        date_time=date_time,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner='Semgrep'
    )
    trend_update(username=username)
    subject = "Archery Tool Scan Status - semgrep Report Uploaded"
    message = (
        "semgrep Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("semgrep", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
