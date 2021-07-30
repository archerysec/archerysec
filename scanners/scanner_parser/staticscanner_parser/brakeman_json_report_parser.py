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
severity = ""
References = ""
false_positive = ""


def brakeman_report_json(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    :username:
    """
    global false_positive
    date_time = datetime.now()
    vul_col = ""

    # Parser for above json data
    # print(data['warnings'])

    vuln = data["warnings"]

    for vuln_data in vuln:
        try:
            name = vuln_data["warning_type"]
        except Exception as e:
            name = "Not Found"

        try:
            warning_code = vuln_data["warning_code"]
        except Exception as e:
            warning_code = "Not Found"

        try:
            fingerprint = vuln_data["fingerprint"]
        except Exception as e:
            fingerprint = "Not Found"

        try:
            description = vuln_data["message"]
        except Exception as e:
            description = "Not Found"

        try:
            check_name = vuln_data["check_name"]
        except Exception as e:
            check_name = "Not Found"

        try:
            severity = vuln_data["confidence"]
            if severity == "Weak":
                severity = "Low"
        except Exception as e:
            severity = "Not Found"

        try:
            file = vuln_data["file"]
        except Exception as e:
            file = "Not Found"

        try:
            line = vuln_data["line"]
        except Exception as e:
            line = "Not Found"

        try:
            link = vuln_data["link"]
        except Exception as e:
            link = "Not Found"

        try:
            code = vuln_data["code"]
        except Exception as e:
            code = "Not Found"

        try:
            render_path = vuln_data["render_path"]
        except Exception as e:
            render_path = "Not Found"

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

        dup_data = str(name) + str(severity) + str(file)

        duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

        match_dup = StaticScanResultsDb.objects.filter(dup_hash=duplicate_hash).values(
            "dup_hash"
        )
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = "No"

            false_p = StaticScanResultsDb.objects.filter(
                false_positive_hash=duplicate_hash
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
                title=name,
                description=str(description)
                + "\n\n"
                + str(code)
                + "\n\n"
                + str(render_path),
                severity=severity,
                fileName=file,
                references=link,
                scanner="Brakeman",
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
                title=name,
                description=str(description)
                + "\n\n"
                + str(code)
                + "\n\n"
                + str(render_path),
                severity=severity,
                fileName=file,
                references=link,
                scanner="Brakeman",
            )
            save_all.save()

    all_findbugs_data = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, false_positive="No", vuln_duplicate="No"
    )

    duplicate_count = StaticScanResultsDb.objects.filter(
        scan_id=scan_id, vuln_duplicate="Yes"
    )

    total_vul = len(all_findbugs_data)
    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

    StaticScansDb.objects.filter(scan_id=scan_id).update(
        date_time=date_time,
        total_vul=total_vul,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        total_dup=total_duplicate,
        scanner="Brakeman",
    )
    trend_update()
    subject = "Archery Tool Scan Status - brakeman Report Uploaded"
    message = (
        "brakeman Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (Target, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
