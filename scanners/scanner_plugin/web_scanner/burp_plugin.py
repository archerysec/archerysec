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

from PyBurprestapi import burpscanner
import os
import json
import time
import xml.etree.ElementTree as ET
import base64
from webscanners.models import burp_scan_db, burp_scan_result_db
import uuid
from django.shortcuts import HttpResponse
# from django.core.mail import send_mail
from webscanners import email_notification
from archerysettings import load_settings
import hashlib

# Setting file importing
setting_file = os.getcwd() + '/' + 'apidata.json'

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
dec_res = ""
dec_req = ""
vul_col = ""


class burp_scans(object):
    """
    Burp Scanner Plugin for Archery.
    """

    def __init__(self, project_id, scan_url, scan_id):
        """

        :param project_id:
        :param scan_url:
        :param scan_id:
        """

        self.project_id = project_id
        self.scan_url = scan_url
        self.scan_id = scan_id

    def scan_launch(self):
        """
        The function trigger the scans.
        """

        settings = load_settings.ArcherySettings(setting_file)
        burp_host = settings.burp_host()
        burp_port = settings.burp_port()

        global vuln_id, burp_status
        # try:
        #     with open(setting_file, 'r+') as f:
        #         data = json.load(f)
        #         burp_path = data['burp_path']
        #         burp_port = data['burp_port']
        # except Exception as e:
        #     print e
        print self.project_id
        print self.scan_url
        time.sleep(15)
        host = 'http://' + burp_host + ':' + burp_port
        bi = burpscanner.BurpApi(host)
        bi.burp_scope_add(self.scan_url)
        bi.burp_spider(self.scan_url)
        time.sleep(15)
        bi.burp_active_scan(self.scan_url)
        print "Project_id", self.project_id
        while (int(burp_status) < 100):
            scan_status = bi.burp_scan_status()
            dat_status = scan_status.data
            for key, item in dat_status.iteritems():
                burp_status = item
                print "Burp Scan Status :", burp_status
                burp_scan_db.objects.filter(
                    scan_id=self.scan_id).update(
                    scan_status=burp_status)
                time.sleep(5)
        burp_status = "100"
        # if burp_status == '100':
        #     burp_status = "0"
        # else:
        #     print "Scan Continue..."
        print "Result Extracting........"
        time.sleep(10)
        print "Result Extracted........"
        scan_result = bi.scan_report(self.scan_url, 'XML')
        result_xml = scan_result.data
        xml_data = ET.fromstring(result_xml)
        do_scan_dat = burp_scans(self.project_id, self.scan_url, self.scan_id)
        do_scan_dat.burp_scan_data(xml_data)

    def burp_scan_data(self, xml_data):
        """
        The function parse the burp result as xml data
        and stored into archery database.
        :param xml_data:
        :return:
        """
        global vuln_id, burp_status, vul_col
        for issue in xml_data:
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
                if data.tag == "issueBackground":
                    global issueBackground
                    if data.text is None:
                        issueBackground = "NA"
                    else:
                        issueBackground = data.text
                if data.tag == "remediationBackground":
                    global remediationBackground
                    if data.text is None:
                        remediationBackground = "NA"
                    else:
                        remediationBackground = data.text
                if data.tag == "references":
                    global references
                    if data.text is None:
                        references = "NA"
                    else:
                        references = data.text
                if data.tag == "vulnerabilityClassifications":
                    global vulnerabilityClassifications
                    if data.text is None:
                        vulnerabilityClassifications = "NA"
                    else:
                        vulnerabilityClassifications = data.text
                if data.tag == "issueDetail":
                    global issueDetail
                    if data.text is None:
                        issueDetail = "NA"
                    else:
                        issueDetail = data.text
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
                            global dec_req
                            reqst = d.text
                            dec_req = base64.b64decode(reqst)  # reqst

                        if req == "response":
                            global dec_res
                            res_dat = d.text
                            dec_res = base64.b64decode(res_dat)  # res_dat

                        for key, items in met.iteritems():
                            global methods
                            if key == "method":
                                methods = items
            global vul_col
            if severity == 'High':
                vul_col = "important"
            elif severity == 'Medium':
                vul_col = "warning"
            elif severity == 'Low':
                vul_col = "info"
            else:
                vul_col = "info"

            dup_data = name + location + severity
            duplicate_hash = hashlib.sha1(dup_data).hexdigest()

            match_dup = burp_scan_result_db.objects.filter(
                dup_hash=duplicate_hash).values('dup_hash').distinct()
            lenth_match = len(match_dup)

            if lenth_match == 1:
                duplicate_vuln = 'Yes'
            elif lenth_match == 0:
                duplicate_vuln = 'No'
            else:
                duplicate_vuln = 'None'

            try:
                data_dump = burp_scan_result_db(
                    scan_id=self.scan_id,
                    types=types, method=methods,
                    scan_request=dec_req,
                    scan_response=dec_res,
                    project_id=self.project_id,
                    vuln_id=vuln_id,
                    serialNumber=serialNumber,
                    name=name,
                    host=host,
                    path=path,
                    location=location,
                    severity=severity,
                    severity_color=vul_col,
                    confidence=confidence,
                    issueBackground=issueBackground,
                    remediationBackground=remediationBackground,
                    references=references,
                    vulnerabilityClassifications=vulnerabilityClassifications,
                    issueDetail=issueDetail,
                    requestresponse=requestresponse,
                    false_positive='No',
                    vuln_status='Open',
                    dup_hash=duplicate_hash,
                    vuln_duplicate=duplicate_vuln
                )
                data_dump.save()
            except Exception as e:
                print e
        burp_all_vul = burp_scan_result_db.objects.filter(scan_id=self.scan_id)
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))
        total_info = len(burp_all_vul.filter(severity="Information"))
        total_duplicate = len(burp_all_vul.filter(vuln_duplicate='Yes'))
        burp_scan_db.objects.filter(scan_id=self.scan_id).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate
        )
        try:
            email_notification.email_notify()
        except Exception as e:
            print e
        HttpResponse(status=201)
