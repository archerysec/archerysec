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
from staticscanners.models import StaticScansDb, StaticScanResultsDb
from utility.email_notify import email_sch_notify

scan_id = None
rescan_id = None
scan_date = None
project_id = None
vuln_id = None
source_line = None
line_number = None
code = None
issue_confidence = None
line_range = None
test_id = None
issue_severity = None
issue_text = None
test_name = None
filename = None
more_info = None
vul_col = None
total_vul = ''
total_high = ''
total_medium = ''
total_low = ''


def bandit_report_json(data, project_id, scan_id):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col, issue_severity, test_name, filename, line_number, code, issue_confidence, line_range, test_id, issue_text, more_info, total_vul, total_high, total_medium, total_low
    for key, items in data.items():
        if key == "results":
            for res in items:
                for key, value in res.items():
                    if key == "line_number":
                        global line_number
                        if value is None:
                            line_number = "NA"
                        else:
                            line_number = value
                    if key == "code":
                        global code
                        if value is None:
                            code = "NA"
                        else:
                            code = value
                    if key == "issue_confidence":
                        global issue_confidence
                        if value is None:
                            issue_confidence = "NA"
                        else:
                            issue_confidence = value
                    if key == "line_range":
                        global line_range
                        if value is None:
                            line_range = "NA"
                        else:
                            line_range = value
                    if key == "test_id":
                        global test_id
                        if value is None:
                            test_id = "NA"
                        else:
                            test_id = value
                    if key == "issue_severity":
                        global issue_severity
                        if value is None:
                            issue_severity = "NA"
                        else:
                            issue_severity = value
                    if key == "issue_text":
                        global issue_text
                        if value is None:
                            issue_text = "NA"
                        else:
                            issue_text = value
                    if key == "test_name":
                        global test_name
                        if value is None:
                            test_name = "NA"
                        else:
                            test_name = value
                    if key == "filename":
                        global filename
                        if value is None:
                            filename = "NA"
                        else:
                            filename = value
                    if key == "more_info":
                        global more_info
                        if value is None:
                            more_info = "NA"
                        else:
                            more_info = value

                date_time = datetime.now()
                vul_id = uuid.uuid4()

                if issue_severity == "HIGH":
                    vul_col = "danger"
                    issue_severity = 'High'

                elif issue_severity == "MEDIUM":
                    vul_col = "warning"
                    issue_severity = 'Medium'

                elif issue_severity == "LOW":
                    vul_col = "info"
                    issue_severity = 'Low'

                dup_data = test_name + filename + issue_severity
                duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()

                match_dup = (
                    StaticScanResultsDb.objects.filter(
                         dup_hash=duplicate_hash
                    )
                    .values("dup_hash")
                    .distinct()
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
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        vuln_id=vul_id,
                        severity=issue_severity,
                        title=test_name,
                        fileName=filename,
                        description=str(issue_text) + '\n\n' + str(code) + '\n\n' + str(line_range),
                        references=more_info,
                        severity_color=vul_col,
                        false_positive=false_positive,
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,

                        scanner='Bandit',
                    )
                    save_all.save()

                else:
                    duplicate_vuln = "Yes"

                    save_all = StaticScanResultsDb(
                        scan_id=scan_id,
                        date_time=date_time,
                        project_id=project_id,
                        vuln_id=vul_id,
                        severity=issue_severity,
                        title=test_name,
                        fileName=filename,
                        description=str(issue_text) + '\n\n' + str(code) + '\n\n' + str(line_range),
                        references=more_info,
                        severity_color=vul_col,
                        false_positive="Duplicate",
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,

                        scanner='Bandit',

                    )
                    save_all.save()

        all_bandit_data = StaticScanResultsDb.objects.filter(
             scan_id=scan_id, false_positive="No"
        )

        duplicate_count = StaticScanResultsDb.objects.filter(
             scan_id=scan_id, vuln_duplicate="Yes"
        )

        total_vul = len(all_bandit_data)
        total_high = len(all_bandit_data.filter(severity="High"))
        total_medium = len(all_bandit_data.filter(severity="Medium"))
        total_low = len(all_bandit_data.filter(severity="Low"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))

        StaticScansDb.objects.filter( scan_id=scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate,
        )
    trend_update()
    subject = "Archery Tool Scan Status - Bandit Report Uploaded"
    message = (
        "Bandit Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (scan_id, total_vul, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)
