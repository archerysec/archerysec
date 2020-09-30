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


from webscanners.models import webinspect_scan_result_db, webinspect_scan_db
import uuid
import hashlib

from webscanners.zapscanner.views import email_sch_notify

url = None
Scheme = None
Host = None
Port = None
AttackMethod = None
VulnerableSession = None
TriggerSession = None
VulnerabilityID = None
Severity = None
Name = None
ReportSection = None
HighlightSelections = None
RawResponse = None
SectionText = None
severity_name = None
vuln_id = None
vul_col = None
false_positive = None


def xml_parser(root,
               project_id,
               scan_id, username):
    global url, \
        Scheme, \
        Host, \
        Port, \
        AttackMethod, \
        VulnerableSession, \
        TriggerSession, \
        VulnerabilityID, \
        Severity, \
        Name, \
        ReportSection, \
        HighlightSelections, \
        RawResponse, \
        SectionText, \
        vuln_id, severity_name, vul_col

    for data in root:
        for issues in data:
            for issue in issues:
                if issue.tag == 'URL':
                    url = issue.text

                if issue.tag == 'Host':
                    Host = issue.text

                if issue.tag == 'Port':
                    Port = issue.text

                if issue.tag == 'AttackMethod':
                    AttackMethod = issue.text

                if issue.tag == 'VulnerableSession':
                    VulnerableSession = issue.text

                if issue.tag == 'TriggerSession':
                    TriggerSession = issue.text

                if issue.tag == 'VulnerabilityID':
                    VulnerabilityID = issue.text

                if issue.tag == 'Severity':
                    Severity = issue.text

                if issue.tag == 'Name':
                    Name = issue.text

                if issue.tag == 'ReportSection':
                    ReportSection = issue.text

                if issue.tag == 'HighlightSelections':
                    HighlightSelections = issue.text

                if issue.tag == 'RawResponse':
                    RawResponse = issue.text

                for d_issue in issue:
                    if d_issue.tag == 'SectionText':
                        SectionText = issue.text

                vuln_id = uuid.uuid4()

            if Severity == "4":
                Severity = 'High'
                vul_col = "danger"

            elif Severity == "3":
                Severity = 'High'
                vul_col = 'danger'

            elif Severity == "2":
                Severity = 'Medium'
                vul_col = "warning"

            elif Severity == '1':
                Severity = 'Low'
                vul_col = "info"

            else:
                Severity = 'Low'
                vul_col = "info"

            dup_data = Name + url + Severity
            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

            match_dup = webinspect_scan_result_db.objects.filter(username=username,
                                                                 dup_hash=duplicate_hash).values('dup_hash').distinct()
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                false_p = webinspect_scan_result_db.objects.filter(username=username,
                                                                   false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                global false_positive
                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                elif lenth_match == 0:
                    false_positive = 'No'
                else:
                    false_positive = 'No'

                if Name is None:
                    print(Name)
                else:
                    dump_data = webinspect_scan_result_db(scan_id=scan_id,
                                                          vuln_id=vuln_id,
                                                          vuln_url=url,
                                                          host=Host,
                                                          port=Port,
                                                          attackmethod=AttackMethod,
                                                          vulnerablesession=VulnerableSession,
                                                          triggerSession=TriggerSession,
                                                          vulnerabilityID=VulnerabilityID,
                                                          severity=Severity,
                                                          name=Name,
                                                          reportSection=ReportSection,
                                                          highlightSelections=HighlightSelections,
                                                          rawResponse=RawResponse,
                                                          SectionText=SectionText,
                                                          severity_name=severity_name,
                                                          vuln_color=vul_col,
                                                          false_positive=false_positive,
                                                          vuln_status='Open',
                                                          dup_hash=duplicate_hash,
                                                          vuln_duplicate=duplicate_vuln,
                                                          project_id=project_id,
                                                          username=username
                                                          )
                    dump_data.save()

            else:
                duplicate_vuln = 'Yes'

                dump_data = webinspect_scan_result_db(scan_id=scan_id,
                                                      vuln_id=vuln_id,
                                                      vuln_url=url,
                                                      host=Host,
                                                      port=Port,
                                                      attackmethod=AttackMethod,
                                                      vulnerablesession=VulnerableSession,
                                                      triggerSession=TriggerSession,
                                                      vulnerabilityID=VulnerabilityID,
                                                      severity=Severity,
                                                      name=Name,
                                                      reportSection=ReportSection,
                                                      highlightSelections=HighlightSelections,
                                                      rawResponse=RawResponse,
                                                      SectionText=SectionText,
                                                      severity_name=severity_name,
                                                      vuln_color=vul_col,
                                                      false_positive='Duplicate',
                                                      vuln_status='Duplicate',
                                                      dup_hash=duplicate_hash,
                                                      vuln_duplicate=duplicate_vuln,
                                                      project_id=project_id,
                                                      username=username
                                                      )
                dump_data.save()

        webinspect_all_vul = webinspect_scan_result_db.objects.filter(username=username, scan_id=scan_id,
                                                                      false_positive='No')

        duplicate_count = webinspect_scan_result_db.objects.filter(username=username, scan_id=scan_id,
                                                                   vuln_duplicate='Yes')

        total_critical = len(webinspect_all_vul.filter(severity='Critical'))
        total_high = len(webinspect_all_vul.filter(severity="High"))
        total_medium = len(webinspect_all_vul.filter(severity="Medium"))
        total_low = len(webinspect_all_vul.filter(severity="Low"))
        total_info = len(webinspect_all_vul.filter(severity="Information"))
        total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))
        total_vul = total_critical + total_high + total_medium + total_low + total_info

        webinspect_scan_db.objects.filter(username=username,
                                          scan_id=scan_id).update(total_vul=total_vul,
                                                                  high_vul=total_high,
                                                                  medium_vul=total_medium,
                                                                  low_vul=total_low,
                                                                  critical_vul=total_critical,
                                                                  info_vul=total_info,
                                                                  total_dup=total_duplicate
                                                                  )
    subject = 'Archery Tool Scan Status - Webinspect Report Uploaded'
    message = 'Webinspect Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (Host, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
