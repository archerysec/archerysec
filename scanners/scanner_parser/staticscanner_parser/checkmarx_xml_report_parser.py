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

from staticscanners.models import checkmarx_scan_db, checkmarx_scan_results_db
import uuid
import hashlib
from datetime import datetime
import json

from webscanners.zapscanner.views import email_sch_notify

vul_col = ''
severity = ''
project = ''
result = ''
result_data = ''
file_name = ''
inst = ''
code_data = ''


def checkmarx_report_xml(data, project_id, scan_id, username):
    """

    :param data:
    :param project_id:
    :param scan_id:
    :return:
    """
    print(data)

    global vul_col, project, result, result_data, file_name, inst, code_data
    project = data.attrib['ProjectName']
    scan_details = data.attrib
    for dat in data:
        query = dat.attrib
        name = dat.attrib['name']
        severity = dat.attrib['Severity']
        code_data = []
        result_data_all = []
        for dd in dat:
            result_data = dd.attrib
            file_name = dd.attrib['FileName']

            # res_inst = {}
            # res_inst[dd.attrib] = ['']
            result_data_all.append(dd.attrib)

            for d in dd.findall(".//Code"):
                result = d.text
                instance = {}
                instance[file_name] = d.text
                code_data.append(instance)
        print(severity)
        if severity == "High":
            vul_col = "danger"
        elif severity == 'Medium':
            vul_col = "warning"
        elif severity == 'Low':
            vul_col = "info"
        else:
            severity = 'Low'
            vul_col = "info"
        vul_id = uuid.uuid4()

        dup_data = str(name) + str(severity) + str(file_name)
        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
        match_dup = checkmarx_scan_results_db.objects.filter(username=username,
                                                             dup_hash=duplicate_hash).values('dup_hash')
        lenth_match = len(match_dup)
        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = checkmarx_scan_results_db.objects.filter(username=username,
                                                               false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)
            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            save_all = checkmarx_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Open',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive=false_positive,

                name=name,
                severity=severity,
                query=query,
                result=code_data,
                scan_details=scan_details,
                result_data=result_data_all,
                file_name=file_name,
                username=username,
            )
            save_all.save()

        else:
            duplicate_vuln = 'Yes'

            save_all = checkmarx_scan_results_db(
                vuln_id=vul_id,
                scan_id=scan_id,
                project_id=project_id,
                vul_col=vul_col,
                vuln_status='Duplicate',
                dup_hash=duplicate_hash,
                vuln_duplicate=duplicate_vuln,
                false_positive='Duplicate',
                name=name,
                severity=severity,
                query=query,
                result=code_data,
                scan_details=scan_details,
                result_data=result_data_all,
                file_name=file_name,
                username=username,
            )
            save_all.save()

    all_findbugs_data = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = checkmarx_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                               vuln_duplicate='Yes')


    total_high = len(all_findbugs_data.filter(severity="High"))
    total_medium = len(all_findbugs_data.filter(severity="Medium"))
    total_low = len(all_findbugs_data.filter(severity="Low"))
    total_vul = len(all_findbugs_data)
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

    checkmarx_scan_db.objects.filter(username=username, scan_id=scan_id).update(
        project_name=project,
        total_vuln=total_vul,
        SEVERITY_HIGH=total_high,
        SEVERITY_MEDIUM=total_medium,
        SEVERITY_LOW=total_low,
        total_dup=total_duplicate
    )
    subject = 'Archery Tool Scan Status - checkmarx Report Uploaded'
    message = 'checkmarx Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % ("checkmarx", total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
