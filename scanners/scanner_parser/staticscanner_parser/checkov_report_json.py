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


def checkov_report_json(data, project_id, scan_id, request):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    date_time = datetime.now()
    global vul_col, severity

    api_key = request.META.get("HTTP_X_API_KEY")
    key_object = OrgAPIKey.objects.filter(api_key=api_key).first()
    if str(request.user) == 'AnonymousUser':
        organization = key_object.organization
    else:
        organization = request.user.organization
    for check in data:
        for failed_check in check['results']['failed_checks']:
            check_id = failed_check['check_id']
            bc_check_id = failed_check['bc_check_id']
            check_name = failed_check['check_name']
            file_path = failed_check['file_path']
            file_abs_path = failed_check['file_abs_path']
            repo_file_path = failed_check['repo_file_path']
            file_line_range = failed_check['file_line_range']
            resource = failed_check['resource']
            code_block = "\n".join([line[1] for line in failed_check['code_block']])
            severity = failed_check['severity']
            fixed_definition = failed_check['fixed_definition']
            guideline = failed_check['guideline']
            
            if severity == "Critical":
                vul_col = "critical"

            elif severity == "High":
                vul_col = "danger"

            elif severity == "Medium":
                vul_col = "warning"

            elif severity == "Low":
                vul_col = "info"

            else:
                severity = "High"
                vul_col = "danger"

            vul_id = uuid.uuid4()

            dup_data = str(check_name) + str(severity) + str(resource)

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
                    title=check_name,
                    fileName=str(file_path),
                    severity=severity,
                    filePath=str(file_path),
                    solution=str(fixed_definition),
                    description=str(check_id)
                    + "\n\n"
                    + str(bc_check_id)
                    + "\n\n"
                    + str(file_abs_path)
                    + "\n\n"
                    + str(repo_file_path)
                    + "\n\n"
                    + str(file_line_range)
                    + "\n\n"
                    + str(code_block),
                    references = guideline,
                    scanner="checkov",
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
                    title=check_name,
                    fileName=str(file_path),
                    severity=severity,
                    filePath=str(file_path),
                    solution=str(fixed_definition),
                    description=str(check_id)
                    + "\n\n"
                    + str(bc_check_id)
                    + "\n\n"
                    + str(file_abs_path)
                    + "\n\n"
                    + str(repo_file_path)
                    + "\n\n"
                    + str(file_line_range)
                    + "\n\n"
                    + str(code_block),
                    scanner="checkov",
                    references = guideline,
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
        scanner="checkov",
        organization=organization,
    )
    trend_update()
    subject = "ArcherySec Tool Scan Status - checkov Report Uploaded"
    message = (
        "Nodejsscan Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % ("Nodejsscan", total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


parser_header_dict = {
    "checkov": {
        "displayName": "checkov Scanner",
        "dbtype": "StaticScans",
        "dbname": "checkov",
        "type": "JSON",
        "parserFunction": checkov_report_json,
        "icon": "/static/tools/checkov.png",
    }
}
