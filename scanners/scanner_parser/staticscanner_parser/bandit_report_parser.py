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

from staticscanners.models import bandit_scan_db, bandit_scan_results_db
import json
import uuid
from networkscanners.models import nessus_report_db, nessus_scan_db
import hashlib
from datetime import datetime

from webscanners.zapscanner.views import email_sch_notify

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


def bandit_report_json(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col, issue_severity, test_name, filename, line_number, code, issue_confidence, line_range, \
        test_id, issue_text, more_info
    for key, items in data.items():
        if key == 'results':
            for res in items:
                for key, value in res.items():
                    if key == 'line_number':
                        global line_number
                        if value is None:
                            line_number = "NA"
                        else:
                            line_number = value
                    if key == 'code':
                        global code
                        if value is None:
                            code = "NA"
                        else:
                            code = value
                    if key == 'issue_confidence':
                        global issue_confidence
                        if value is None:
                            issue_confidence = "NA"
                        else:
                            issue_confidence = value
                    if key == 'line_range':
                        global line_range
                        if value is None:
                            line_range = "NA"
                        else:
                            line_range = value
                    if key == 'test_id':
                        global test_id
                        if value is None:
                            test_id = "NA"
                        else:
                            test_id = value
                    if key == 'issue_severity':
                        global issue_severity
                        if value is None:
                            issue_severity = "NA"
                        else:
                            issue_severity = value
                    if key == 'issue_text':
                        global issue_text
                        if value is None:
                            issue_text = "NA"
                        else:
                            issue_text = value
                    if key == 'test_name':
                        global test_name
                        if value is None:
                            test_name = "NA"
                        else:
                            test_name = value
                    if key == 'filename':
                        global filename
                        if value is None:
                            filename = "NA"
                        else:
                            filename = value
                    if key == 'more_info':
                        global more_info
                        if value is None:
                            more_info = "NA"
                        else:
                            more_info = value

                date_time = datetime.now()
                vul_id = uuid.uuid4()

                if issue_severity == "HIGH":
                    vul_col = "danger"

                elif issue_severity == "MEDIUM":
                    vul_col = 'warning'

                elif issue_severity == "LOW":
                    vul_col = "info"

                dup_data = test_name + filename + issue_severity
                duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

                match_dup = bandit_scan_results_db.objects.filter(username=username,
                                                                  dup_hash=duplicate_hash).values('dup_hash').distinct()
                lenth_match = len(match_dup)

                if lenth_match == 0:
                    duplicate_vuln = 'No'

                    false_p = bandit_scan_results_db.objects.filter(username=username,
                                                                    false_positive_hash=duplicate_hash)
                    fp_lenth_match = len(false_p)

                    if fp_lenth_match == 1:
                        false_positive = 'Yes'
                    else:
                        false_positive = 'No'

                    save_all = bandit_scan_results_db(
                        scan_id=scan_id,
                        # rescan_id = rescan_id,
                        scan_date=date_time,
                        project_id=project_id,
                        vuln_id=vul_id,
                        # source_line=source_line,
                        line_number=line_number,
                        code=code,
                        issue_confidence=issue_confidence,
                        line_range=line_range,
                        test_id=test_id,
                        issue_severity=issue_severity,
                        issue_text=issue_text,
                        test_name=test_name,
                        filename=filename,
                        more_info=more_info,
                        vul_col=vul_col,
                        false_positive=false_positive,
                        vuln_status='Open',
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        username=username,
                    )
                    save_all.save()

                else:
                    duplicate_vuln = 'Yes'

                    save_all = bandit_scan_results_db(
                        scan_id=scan_id,
                        # rescan_id = rescan_id,
                        scan_date=date_time,
                        project_id=project_id,
                        vuln_id=vul_id,
                        # source_line=source_line,
                        line_number=line_number,
                        code=code,
                        issue_confidence=issue_confidence,
                        line_range=line_range,
                        test_id=test_id,
                        issue_severity=issue_severity,
                        issue_text=issue_text,
                        test_name=test_name,
                        filename=filename,
                        more_info=more_info,
                        vul_col=vul_col,
                        false_positive='Duplicate',
                        vuln_status='Duplicate',
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        username=username,
                    )
                    save_all.save()

        all_bandit_data = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

        duplicate_count = bandit_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_duplicate='Yes')

        total_vul = len(all_bandit_data)
        total_high = len(all_bandit_data.filter(issue_severity="HIGH"))
        total_medium = len(all_bandit_data.filter(issue_severity="MEDIUM"))
        total_low = len(all_bandit_data.filter(issue_severity="LOW"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

        bandit_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )

    subject = 'Archery Tool Scan Status - Bandit Report Uploaded'
    message = 'Bandit Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (scan_id, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
