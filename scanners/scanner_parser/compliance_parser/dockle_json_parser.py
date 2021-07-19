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


import uuid

from compliance.models import DockleScanDb, DockleScanResultsDb
from utility.email_notify import email_sch_notify

status = None
controls_results_message = None
vuln_col = ""


def dockle_report_json(data, project_id, scan_id, ):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col

    for vuln in data["details"]:
        code = vuln["code"]
        title = vuln["title"]
        level = vuln["level"]
        alerts = vuln["alerts"][0]

        if level == "FATAL":
            vul_col = "danger"

        elif level == "PASS":
            vul_col = "warning"

        elif level == "WARN":
            vul_col = "warning"

        elif level == "INFO":
            vul_col = "info"

        vul_id = uuid.uuid4()

        save_all = DockleScanResultsDb(
            scan_id=scan_id,
            project_id=project_id,
            vul_col=vul_col,
            vuln_id=vul_id,
            code=code,
            title=title,
            alerts=alerts,
            level=level,
        )
        save_all.save()

    all_dockle_data = DockleScanResultsDb.objects.filter(
        scan_id=scan_id
    )

    total_vul = len(all_dockle_data)
    dockle_failed = len(all_dockle_data.filter(level="FATAL"))
    dockle_passed = len(all_dockle_data.filter(level="PASS"))
    dockle_warn = len(all_dockle_data.filter(level="WARN"))
    dockle_info = len(all_dockle_data.filter(level="INFO"))
    total_duplicate = len(all_dockle_data.filter(level="Yes"))

    DockleScanDb.objects.filter(scan_id=scan_id).update(
        total_vuln=total_vul,
        dockle_fatal=dockle_failed,
        dockle_warn=dockle_warn,
        dockle_info=dockle_info,
        dockle_pass=dockle_passed,
        total_dup=total_duplicate,
    )
    subject = "Archery Tool Scan Status - dockle Report Uploaded"
    message = (
        "dockle Scanner has completed the scan "
        "  %s <br> Total: %s <br>Failed: %s <br>"
        "failed: %s <br>Skipped %s"
        % (scan_id, total_vul, dockle_failed, dockle_warn, dockle_passed)
    )

    email_sch_notify(subject=subject, message=message)
