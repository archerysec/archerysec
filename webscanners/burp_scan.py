from PyBurprestapi import burpscanner
import os
import json
from scanners import burpscan
import time
import xml.etree.ElementTree as ET
import base64
from webscanners.models import burp_scan_db, burp_scan_result_db
import uuid
from django.shortcuts import HttpResponse

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

api_key_path = os.getcwd() + '/' + 'apidata.json'


def scan_lauch(project_id, scan_url, scan_id):
    global vuln_id, burp_status
    # Get the burp path
    try:
        with open(api_key_path, 'r+') as f:
            data = json.load(f)
            burp_path = data['zap_port']
    except Exception as e:
        print e

    print project_id
    print scan_url

    time.sleep(15)

    host = 'http://localhost:8090'

    bi = burpscanner.BurpApi(host)

    bi.burp_scope_add(scan_url)
    bi.burp_spider(scan_url)
    time.sleep(15)

    bi.burp_active_scan(scan_url)
    print "Project_id", project_id

    while (int(burp_status) < 100):
        scan_status = bi.burp_scan_status()
        dat_status = scan_status.data
        for key, item in dat_status.iteritems():
            burp_status = item
            print "Burp Scan Status :", burp_status
            burp_scan_db.objects.filter(scan_id=scan_id).update(scan_status=burp_status)
            time.sleep(5)
    if burp_status == '100':
        burp_status = "0"
    else:
        return burp_status

    print "Result Extracting........"
    time.sleep(10)
    print "Result Extracted........"
    scan_result = bi.scan_report(scan_url, 'XML')
    result_xml = scan_result.data

    root = ET.fromstring(result_xml)
    print root

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
                        dec_req = base64.b64decode(reqst)

                    if req == "response":
                        global dec_res
                        res_dat = d.text
                        dec_res = base64.b64decode(res_dat)

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

        try:
            data_dump = burp_scan_result_db(scan_id=scan_id, types=types, method=methods, scan_request=dec_req,
                                            scan_response=dec_res,
                                            project_id=project_id, vuln_id=vuln_id,
                                            serialNumber=serialNumber, name=name, host=host,
                                            path=path, location=location,
                                            severity=severity, severity_color=vul_col, confidence=confidence,
                                            issueBackground=issueBackground,
                                            remediationBackground=remediationBackground, references=references,
                                            vulnerabilityClassifications=vulnerabilityClassifications,
                                            issueDetail=issueDetail, requestresponse=requestresponse
                                            )
            data_dump.save()
        except Exception as e:
            print e

    burp_all_vul = burp_scan_result_db.objects.filter(scan_id=scan_id)

    total_vul = len(burp_all_vul)
    total_high = len(burp_all_vul.filter(severity="High"))
    total_medium = len(burp_all_vul.filter(severity="Medium"))
    total_low = len(burp_all_vul.filter(severity="Low"))
    total_info = len(burp_all_vul.filter(severity="Information"))

    burp_scan_db.objects.filter(scan_id=scan_id).update(total_vul=total_vul, high_vul=total_high,
                                                        medium_vul=total_medium, low_vul=total_low)

    HttpResponse(status=201)
