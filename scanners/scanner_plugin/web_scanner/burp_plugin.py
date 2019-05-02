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

from PyBurprestapi import burpscanner
import json
import time
import base64
from webscanners.models import burp_scan_db, burp_scan_result_db, burp_issue_definitions
import uuid
from django.shortcuts import HttpResponse
from webscanners import email_notification
import hashlib
from archerysettings.models import burp_setting_db
from datetime import datetime
from notifications.signals import notify
from django.conf import settings
from archerysettings.models import email_db
from django.core.mail import send_mail


def email_notify(user, subject, message):
    all_email = email_db.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb='Email Settings Not Configured')
        pass


class burp_scans(object):
    """
    Burp Scanner Plugin for Archery.
    """

    project_id = None
    target_url = None
    scan_ip = None
    burp_status = 0
    name = "NA"
    host = "NA"
    path = "NA"
    location = "NA"
    severity = "NA"
    confidence = "NA"
    references = "NA"
    vul_col = "NA"
    false_positive = None
    data = None
    url = "NA"
    request_type = "NA"
    request_datas = "NA"
    response_type = "NA"
    response_datas = "NA"
    was_redirect_followed = "NA"
    issue_remediation = "NA"
    issue_reference = "NA"
    issue_vulnerability_classifications = "NA"

    def __init__(self, project_id, scan_url, scan_id, user):
        """

        :param project_id:
        :param scan_url:
        :param scan_id:
        :param user:
        """

        self.project_id = project_id
        self.scan_url = scan_url
        self.scan_id = scan_id
        self.user = user

    def scan_launch(self):
        """
        The function trigger the scans.
        """
        burp_host = None
        burp_port = None
        burp_api_key = None

        global burp_status, data

        # Load setting parameters from burp_setting_db models
        all_burp_settings = burp_setting_db.objects.all()

        for data in all_burp_settings:
            burp_host = data.burp_url
            burp_port = data.burp_port
            burp_api_key = data.burp_api_key

        date_time = datetime.now()
        scan_dump = burp_scan_db(scan_id=self.scan_id,
                                 project_id=self.project_id,
                                 url=self.scan_url,
                                 date_time=date_time)
        scan_dump.save()

        host = 'http://' + burp_host + ':' + burp_port + '/'
        bi = burpscanner.BurpApi(host, burp_api_key)
        data = '{"urls":["%s"]}' % self.scan_url
        response = bi.scan(data)
        scan_data = response.response_headers
        burp_scan_id = scan_data['location']

        # Email Notification
        message = 'Burp Scan Launched '
        subject = 'Archery Burp Scan Notification'
        email_notify(user=self.user, subject=subject, message=message)

        # Dashboard Notification
        notify.send(self.user, recipient=self.user, verb='Burp Scan Launched')

        scan_info = bi.scan_info(burp_scan_id)
        json_scan_data = json.dumps(scan_info.data)
        scan_info_data = json.loads(json_scan_data)
        scan_status = scan_info_data['scan_metrics']['crawl_and_audit_progress']

        while (int(scan_status) < 100):
            scan_info = bi.scan_info(burp_scan_id)
            json_scan_data = json.dumps(scan_info.data)
            scan_info_data = json.loads(json_scan_data)
            scan_status = scan_info_data['scan_metrics']['crawl_and_audit_progress']
            print("Burp Scan Status :"), scan_status
            burp_scan_db.objects.filter(
                scan_id=self.scan_id).update(
                scan_status=scan_status)
            time.sleep(5)

        scan_info = bi.scan_info(burp_scan_id)
        json_scan_data = json.dumps(scan_info.data)
        scan_info_data = json.loads(json_scan_data)
        scan_data = scan_info_data['issue_events']
        do_scan_dat = burp_scans(self.project_id, self.scan_url, self.scan_id, self.user)
        do_scan_dat.burp_scan_data(scan_data)

    def burp_scan_data(self, scan_data):
        """
        The function parse the burp result as xml data
        and stored into archery database.
        :param xml_data:
        :return:
        """

        global name, origin, confidence, caption, \
            type_index, internal_data, \
            serial_number, path, severity, \
            url, request_type, request_datas, \
            response_type, response_datas, was_redirect_followed, issue_description, \
            issue_remediation, issue_reference, issue_vulnerability_classifications

        for data in scan_data:
            for key, value in data['issue'].items():
                if key == 'name':
                    name = value

                if key == 'origin':
                    origin = value

                if key == 'confidence':
                    confidence = value

                if key == 'evidence':
                    evidence = value
                    if evidence is None:
                        print("Evidence not found")
                    else:
                        try:
                            for e in evidence:
                                for key, value in e.items():
                                    if key == 'request_response':
                                        url = value['url']
                                        was_redirect_followed = value['was_redirect_followed']

                                        for request_data in value['request']:
                                            request_type = request_data['type']
                                            request_datas = base64.b64decode((request_data['data']))

                                        for request_data in value['response']:
                                            response_type = request_data['type']
                                            response_datas = base64.b64decode(request_data['data'])
                        except Exception as e:
                            print(e)

                if key == 'caption':
                    caption = value

                if key == 'type_index':
                    type_index = value

                if key == 'internal_data':
                    internal_data = value

                if key == 'serial_number':
                    serial_number = value

                if key == 'path':
                    path = value

                if key == 'severity':
                    severity = value

            all_issue_definitions = burp_issue_definitions.objects.filter(issue_type_id=type_index)
            for def_data in all_issue_definitions:
                issue_description = def_data.description
                issue_remediation = def_data.remediation
                issue_vulnerability_classifications = def_data.vulnerability_classifications
                issue_reference = def_data.reference

            global vul_col
            if severity == 'high':
                severity = 'High'
                vul_col = "danger"
            elif severity == 'medium':
                severity = 'Medium'
                vul_col = "warning"
            elif severity == 'low':
                severity = 'Low'
                vul_col = "info"
            elif severity == 'info':
                severity = 'Info'
                vul_col = "info"
            else:
                vul_col = "info"

            vuln_id = uuid.uuid4()

            dup_data = name + path + severity
            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()

            match_dup = burp_scan_result_db.objects.filter(
                dup_hash=duplicate_hash).values('dup_hash').distinct()
            lenth_match = len(match_dup)

            if lenth_match == 1:
                duplicate_vuln = 'Yes'
            elif lenth_match == 0:
                duplicate_vuln = 'No'
            else:
                duplicate_vuln = 'None'

            false_p = burp_scan_result_db.objects.filter(
                false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            global false_positive
            if fp_lenth_match == 1:
                false_positive = 'Yes'
            elif lenth_match == 0:
                false_positive = 'No'
            else:
                false_positive = 'No'

            try:
                data_dump = burp_scan_result_db(
                    scan_id=self.scan_id,
                    project_id=self.project_id,
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
                    type_index=type_index,
                    serial_number=serial_number,
                    origin=origin,
                    caption=caption,
                    request_response_url=url,
                    request_response_request_type=request_type,
                    request_response_request_data=request_datas,
                    request_response_response_type=response_type,
                    request_response_response_data=response_datas,
                    was_redirect_followed=was_redirect_followed,
                    description=issue_description,
                    remediation=issue_remediation,
                    reference=issue_reference,
                    vulnerability_classifications=issue_vulnerability_classifications
                )
                data_dump.save()
            except Exception as e:
                print(e)
        burp_all_vul = burp_scan_result_db.objects.filter(scan_id=self.scan_id).values('name', 'severity'
                                                                                       ).distinct()
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))
        total_info = len(burp_all_vul.filter(severity="Info"))
        total_duplicate = len(burp_all_vul.filter(vuln_duplicate='Yes'))
        burp_scan_db.objects.filter(scan_id=self.scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_duplicate
        )
        try:
            email_notification.email_notify()
        except Exception as e:
            print(e)
        HttpResponse(status=201)
