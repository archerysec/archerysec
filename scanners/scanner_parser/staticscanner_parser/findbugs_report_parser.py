#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from staticscanners.models import findbugs_scan_db, findbugs_scan_results_db
import uuid
import hashlib
from datetime import datetime

Details = 'NA'
classname = 'NA'
ShortMessage = 'NA'
sourcepath = 'NA'
sourcefile = 'NA'
LongMessage = 'NA'


def xml_parser(root, project_id, scan_id):
    """

    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """
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
                    vul_col = "important"

                elif priority == '2':
                    risk = 'Medium'
                    vul_col = "warning"

                elif priority == '3':
                    risk = 'Medium'
                    vul_col = "info"

                vul_id = uuid.uuid4()

                dup_data = name + classname + priority

                duplicate_hash = hashlib.sha256(dup_data).hexdigest()

                match_dup = findbugs_scan_results_db.objects.filter(
                    dup_hash=duplicate_hash).values('dup_hash')
                lenth_match = len(match_dup)

                if lenth_match == 1:
                    duplicate_vuln = 'Yes'
                elif lenth_match == 0:
                    duplicate_vuln = 'No'
                else:
                    duplicate_vuln = 'None'

                false_p = findbugs_scan_results_db.objects.filter(
                    false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

            print "zzzzz", sourcefile

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
                risk=risk
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

                findbugs_scan_results_db.objects.filter(scan_id=scan_id, name=name).update(
                    ShortDescription=ShortDescription,
                    Details=Details,
                )

        all_findbugs_data = findbugs_scan_results_db.objects.filter(scan_id=scan_id)

        total_vul = len(all_findbugs_data)
        total_high = len(all_findbugs_data.filter(priority="1"))
        total_medium = len(all_findbugs_data.filter(priority="2"))
        total_low = len(all_findbugs_data.filter(priority="3"))
        total_duplicate = len(all_findbugs_data.filter(vuln_duplicate='Yes'))
        print "total duplicats", total_duplicate

        findbugs_scan_db.objects.filter(scan_id=scan_id).update(
            total_vuln=total_vul,
            SEVERITY_HIGH=total_high,
            SEVERITY_MEDIUM=total_medium,
            SEVERITY_LOW=total_low,
            total_dup=total_duplicate
        )
