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

import base64
from webscanners.models import burp_scan_db, burp_scan_result_db, burp_issue_definitions
import uuid
from django.shortcuts import HttpResponse
# from django.core.mail import send_mail
from webscanners import email_notification
import hashlib

from webscanners.zapscanner.views import email_sch_notify

project_id = None
target_url = None
scan_ip = None
burp_status = 0
serialNumber = ""
types = ""
name = ""
host = ""
path = ""
location = ""
severity = ""
confidence = ""
issueBackground = ""
remediationBackground = ""
references = ""
vulnerabilityClassifications = ""
issueDetail = ""
requestresponse = ""
vuln_id = ""
methods = ""
request_datas = ""
response_datas = ""
vul_col = ""
false_positive = None
issue_description = ''
issue_remediation = ''
issue_reference = ''
issue_vulnerability_classifications = ''


def burp_scan_data(root, project_id, scan_id, username):
    """
    The function parse the burp result as xml data
    and stored into archery database.
    :param xml_data:
    :return:
    """
    global vuln_id, burp_status, vul_col, \
        issue_description, \
        issue_remediation, \
        issue_reference, \
        issue_vulnerability_classifications, \
        vul_col, severity, name, path, host, location, \
        confidence, types, serialNumber, request_datas, response_datas, url
    for issue in root:
        for data in issue.getchildren():
            vuln_id = uuid.uuid4()
            if data.tag == "serialNumber":
                global serialNumber
                if data.text is None:
                    serialNumber = "NA"
                else:
                    serialNumber = data.text
            if data.tag == "type":
                global types
                if data.text is None:
                    types = "NA"
                else:
                    types = data.text
            if data.tag == "name":
                global name

                if data.text is None:
                    name = "NA"
                else:
                    name = data.text
            if data.tag == "host":
                global host
                if data.text is None:
                    host = "NA"
                else:
                    host = data.text
            if data.tag == "path":
                global path
                if data.text is None:
                    path = "NA"
                else:
                    path = data.text
            if data.tag == "location":
                global location
                if data.text is None:
                    location = "NA"
                else:
                    location = data.text
            if data.tag == "severity":
                global severity
                if data.text is None:
                    severity = "NA"
                else:
                    severity = data.text

            if data.tag == "confidence":
                global confidence
                if data.text is None:
                    confidence = "NA"
                else:
                    confidence = data.text
            if data.tag == "requestresponse":
                global requestresponse
                if data.text is None:
                    requestresponse = "NA"
                else:
                    requestresponse = data.text
                for d in data:
                    req = d.tag
                    met = d.attrib
                    if req == "request":
                        global request_datas
                        reqst = d.text
                        request_datas = base64.b64decode(reqst)  # reqst

                    if req == "response":
                        global response_datas
                        res_dat = d.text
                        response_datas = base64.b64decode(res_dat)  # res_dat

                    for key, items in met.items():
                        global methods
                        if key == "method":
                            methods = items

            if data.tag == "issueBackground":
                global issue_description
                if data.text is None:
                    issue_description = "NA"
                else:
                    issue_description = data.text
            if data.tag == "remediationBackground":
                global issue_remediation
                if data.text is None:
                    issue_remediation = "NA"
                else:
                    issue_remediation = data.text
            if data.tag == "references":
                global issue_reference
                if data.text is None:
                    issue_reference = "NA"
                else:
                    issue_reference = data.text
            if data.tag == "vulnerabilityClassifications":
                global issue_vulnerability_classifications
                if data.text is None:
                    issue_vulnerability_classifications = "NA"
                else:
                    issue_vulnerability_classifications = data.text


        if severity == 'High':
            vul_col = "danger"
        elif severity == 'Medium':
            vul_col = "warning"
        elif severity == 'Low':
            vul_col = "info"
        else:
            severity = 'Low'
            vul_col = "info"

        vuln_id = uuid.uuid4()

        dup_data = name + host + severity
        duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

        match_dup = burp_scan_result_db.objects.filter(username=username,
                                                       dup_hash=duplicate_hash).values('dup_hash').distinct()
        lenth_match = len(match_dup)

        if lenth_match == 0:
            duplicate_vuln = 'No'

            false_p = burp_scan_result_db.objects.filter(username=username,
                                                         false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            global false_positive
            if fp_lenth_match == 1:
                false_positive = 'Yes'
            elif lenth_match == 0:
                false_positive = 'No'
            else:
                false_positive = 'No'

            url = host + location

            # all_issue_definitions = burp_issue_definitions.objects.filter(issue_type_id=types)
            # for def_data in all_issue_definitions:
            #     issue_description = def_data.description
            #     issue_remediation = def_data.remediation
            #     issue_vulnerability_classifications = def_data.vulnerability_classifications
            #     issue_reference = def_data.reference

            try:
                data_dump = burp_scan_result_db(
                    scan_id=scan_id,
                    project_id=project_id,
                    vuln_id=vuln_id,
                    name=name,
                    path=path,
                    severity=severity,
                    severity_color=vul_col,
                    confidence=confidence,
                    false_positive=false_positive,
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    type_index=types,
                    serial_number=serialNumber,
                    origin=host,
                    request_response_url=url,
                    request_response_request_data=request_datas,
                    request_response_response_data=response_datas,
                    description=issue_description,
                    remediation=issue_remediation,
                    reference=issue_reference,
                    vulnerability_classifications=issue_vulnerability_classifications,
                    username=username
                )
                data_dump.save()
            except Exception as e:
                print(e)

        else:
            duplicate_vuln = 'Yes'

            try:
                data_dump = burp_scan_result_db(
                    scan_id=scan_id,
                    project_id=project_id,
                    vuln_id=vuln_id,
                    name=name,
                    path=path,
                    severity=severity,
                    severity_color=vul_col,
                    confidence=confidence,
                    false_positive='Duplicate',
                    vuln_status='Duplicate',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln,
                    type_index=types,
                    serial_number=serialNumber,
                    origin=host,
                    request_response_url=url,
                    request_response_request_data=request_datas,
                    request_response_response_data=response_datas,
                    description=issue_description,
                    remediation=issue_remediation,
                    reference=issue_reference,
                    vulnerability_classifications=issue_vulnerability_classifications,
                    username=username
                )
                data_dump.save()
            except Exception as e:
                print(e)

    burp_all_vul = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = burp_scan_result_db.objects.filter(username=username, scan_id=scan_id, vuln_duplicate='Yes')

    total_vul = len(burp_all_vul)
    total_high = len(burp_all_vul.filter(severity="High"))
    total_medium = len(burp_all_vul.filter(severity="Medium"))
    total_low = len(burp_all_vul.filter(severity="Low"))
    total_info = len(burp_all_vul.filter(severity="Information"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))
    burp_scan_db.objects.filter(username=username,
                                scan_id=scan_id).update(
        url=host,
        total_vul=total_vul,
        high_vul=total_high,
        medium_vul=total_medium,
        low_vul=total_low,
        info_vul=total_info,
        total_dup=total_duplicate
    )
    subject = 'Archery Tool Scan Status - Burp Report Uploaded'
    message = 'Burp Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (host, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)

    try:
        email_notification.email_notify()
    except Exception as e:
        print(e)
    HttpResponse(status=201)
