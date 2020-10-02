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

from staticscanners.models import findbugs_scan_db, findbugs_scan_results_db
import uuid
import hashlib
from datetime import datetime

from webscanners.zapscanner.views import email_sch_notify

Details = 'NA'
classname = 'NA'
ShortMessage = 'NA'
sourcepath = 'NA'
sourcefile = 'NA'
LongMessage = 'NA'
name = ''
vul_col = ''
lenth_match = ''
duplicate_hash = ''
vul_id = ''


def xml_parser(root, project_id, scan_id, username):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """
    global name, classname, risk, ShortMessage, LongMessage, sourcepath, vul_col, \
        ShortDescription, Details, lenth_match, duplicate_hash, vul_id
    # print root
    for bug in root:
        if bug.tag == 'BugInstance':
            name = bug.attrib['type']
            priority = bug.attrib['priority']
            for BugInstance in bug:
                if BugInstance.tag == 'ShortMessage':
                    global ShortMessage
                    ShortMessage = BugInstance.text
                if BugInstance.tag == 'LongMessage':
                    global LongMessage
                    LongMessage = BugInstance.text
                if BugInstance.tag == 'Class':
                    global classname
                    classname = BugInstance.attrib['classname']
                if BugInstance.tag == 'SourceLine':
                    global sourcepath, sourcefile
                    sourcepath = BugInstance.attrib['sourcepath']
                    sourcefile = BugInstance.attrib['sourcefile']

                if priority == "1":
                    risk = 'High'
                    vul_col = "danger"

                elif priority == '2':
                    risk = 'Medium'
                    vul_col = "warning"

                elif priority == '3':
                    risk = 'Medium'
                    vul_col = "info"

                vul_id = uuid.uuid4()

                dup_data = name + classname + risk

                duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

                match_dup = findbugs_scan_results_db.objects.filter(username=username,
                                                                    dup_hash=duplicate_hash).values('dup_hash')
                lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                false_p = findbugs_scan_results_db.objects.filter(username=username,
                                                                  false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                save_all = findbugs_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    name=name,
                    priority=priority,
                    ShortMessage=ShortMessage,
                    LongMessage=LongMessage,
                    classname=classname,
                    sourcepath=sourcepath,
                    vul_col=vul_col,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive=false_positive,
                    risk=risk,
                    username=username
                )
                save_all.save()

            else:
                duplicate_vuln = 'Yes'

                save_all = findbugs_scan_results_db(
                    vuln_id=vul_id,
                    scan_id=scan_id,
                    project_id=project_id,
                    name=name,
                    priority=priority,
                    ShortMessage=ShortMessage,
                    LongMessage=LongMessage,
                    classname=classname,
                    sourcepath=sourcepath,
                    vul_col=vul_col,
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    false_positive='Duplicate',
                    risk=risk,
                    username=username
                )
                save_all.save()

        if bug.tag == 'BugPattern':
            for BugPattern in bug:
                name = bug.attrib['type']
                if BugPattern.tag == 'ShortDescription':
                    ShortDescription = BugPattern.text
                if BugPattern.tag == 'Details':
                    global Details
                    Details = BugPattern.text

                findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id, name=name).update(
                    ShortDescription=ShortDescription,
                    Details=Details,
                )

        all_findbugs_data = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                    false_positive='No')

        duplicate_count = findbugs_scan_results_db.objects.filter(username=username, scan_id=scan_id,
                                                                             vuln_duplicate='Yes')

        total_vul = len(all_findbugs_data)
        total_high = len(all_findbugs_data.filter(priority="1"))
        total_medium = len(all_findbugs_data.filter(priority="2"))
        total_low = len(all_findbugs_data.filter(priority="3"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))

        findbugs_scan_db.objects.filter(username=username, scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )

    subject = 'Archery Tool Scan Status - Findbugs Report Uploaded'
    message = 'Findbugs Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (scan_id, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
