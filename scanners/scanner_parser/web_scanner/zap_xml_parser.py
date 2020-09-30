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

from webscanners.models import zap_scan_results_db, zap_scans_db
import uuid
import hashlib
import ast
from webscanners.zapscanner.views import email_sch_notify

spider_status = "0"
scans_status = "0"
spider_alert = ""
target_url = ""
driver = ""
new_uri = ""
cookies = ""
excluded_url = ""
vul_col = ""
note = ""
rtt = ""
tags = ""
timestamp = ""
responseHeader = ""
requestBody = ""
responseBody = ""
requestHeader = ""
cookieParams = ""
res_type = ""
res_id = ""
url = ""
name = "None"
solution = ""
instance = ""
sourceid = ""
pluginid = ""
alert = ""
desc = ""
riskcode = ""
confidence = ""
wascid = ""
risk = ""
reference = ""
false_positive = ""
duplicate_hash = ""
duplicate_vuln = ""
scan_url = ''


def xml_parser(username, root, project_id, scan_id):
    """
    ZAP Proxy scanner xml report parser.
    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """
    global vul_col, \
        confidence, \
        wascid, risk, \
        reference, \
        url, \
        name, \
        solution, \
        instance, \
        sourceid, \
        pluginid, \
        alert, \
        desc, \
        riskcode, vuln_id, false_positive, duplicate_hash, duplicate_vuln, scan_url

    for child in root:
        d = child.attrib
        scan_url = d['name']

    for alert in root.iter('alertitem'):
        inst = []
        for vuln in alert:
            vuln_id = uuid.uuid4()
            if vuln.tag == "pluginid":
                pluginid = vuln.text
            if vuln.tag == "alert":
                alert = vuln.text
            if vuln.tag == "name":
                name = vuln.text
            if vuln.tag == "riskcode":
                riskcode = vuln.text
            if vuln.tag == "confidence":
                confidence = vuln.text
            if vuln.tag == "desc":
                desc = vuln.text
            if vuln.tag == "solution":
                solution = vuln.text
            if vuln.tag == "reference":
                reference = vuln.text
            if vuln.tag == "wascid":
                wascid = vuln.text
            if vuln.tag == "sourceid":
                sourceid = vuln.text

            for instances in vuln:
                for ii in instances:
                    instance = {}
                    instance[ii.tag] = ii.text
                    inst.append(instance)

            if riskcode == "3":
                vul_col = "danger"
                risk = "High"
            elif riskcode == '2':
                vul_col = "warning"
                risk = "Medium"
            elif riskcode == '1':
                vul_col = "info"
                risk = "Low"
            else:
                vul_col = "info"
                risk = "Low"

        if name == "None":
            print(name)
        else:
            dup_data = name + risk + scan_url
            print(dup_data)
            duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
            match_dup = zap_scan_results_db.objects.filter(
                dup_hash=duplicate_hash).values('dup_hash').distinct()
            lenth_match = len(match_dup)

            if lenth_match == 0:
                duplicate_vuln = 'No'

                dump_data = zap_scan_results_db(vuln_id=vuln_id,
                                                vuln_color=vul_col,
                                                scan_id=scan_id,
                                                project_id=project_id,
                                                confidence=confidence,
                                                wascid=wascid,
                                                risk=risk,
                                                reference=reference,
                                                url=url,
                                                name=name,
                                                solution=solution,
                                                param=instance,
                                                sourceid=sourceid,
                                                pluginId=pluginid,
                                                alert=alert,
                                                description=desc,
                                                false_positive=false_positive,
                                                rescan='No',
                                                vuln_status='Open',
                                                dup_hash=duplicate_hash,
                                                vuln_duplicate=duplicate_vuln,
                                                evidence=inst,
                                                username=username
                                                )
                dump_data.save()

            else:
                duplicate_vuln = 'Yes'

                dump_data = zap_scan_results_db(vuln_id=vuln_id,
                                                vuln_color=vul_col,
                                                scan_id=scan_id,
                                                project_id=project_id,
                                                confidence=confidence,
                                                wascid=wascid,
                                                risk=risk,
                                                reference=reference,
                                                url=url,
                                                name=name,
                                                solution=solution,
                                                param=instance,
                                                sourceid=sourceid,
                                                pluginId=pluginid,
                                                alert=alert,
                                                description=desc,
                                                false_positive='Duplicate',
                                                rescan='No',
                                                vuln_status='Duplicate',
                                                dup_hash=duplicate_hash,
                                                vuln_duplicate=duplicate_vuln,
                                                evidence=inst,
                                                username=username
                                                )
                dump_data.save()

            false_p = zap_scan_results_db.objects.filter(
                false_positive_hash=duplicate_hash)
            fp_lenth_match = len(false_p)

            if fp_lenth_match == 1:
                false_positive = 'Yes'
            else:
                false_positive = 'No'

            vul_dat = zap_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            full_data = []
            for data in vul_dat:
                evi = data.evidence
                evi_data = ast.literal_eval(evi)
                for evidence in evi_data:
                    for key, value in evidence.items():
                        if key == 'evidence':
                            key = 'Evidence'

                        if key == 'attack':
                            key = 'Attack'

                        if key == 'uri':
                            key = 'URI'

                        if key == 'method':
                            key = 'Method'

                        if key == 'param':
                            key = 'Parameter'

                        instance = key + ': ' + value

                        full_data.append(instance)
            removed_list_data = ','.join(full_data)
            zap_scan_results_db.objects.filter(username=username, vuln_id=vuln_id).update(param=removed_list_data)

    zap_all_vul = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No')

    duplicate_count = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_duplicate='Yes')

    total_high = len(zap_all_vul.filter(risk="High"))
    total_medium = len(zap_all_vul.filter(risk="Medium"))
    total_low = len(zap_all_vul.filter(risk="Low"))
    total_info = len(zap_all_vul.filter(risk="Informational"))
    total_duplicate = len(duplicate_count.filter(vuln_duplicate='Yes'))
    total_vul = total_high + total_medium + total_low + total_info

    zap_scans_db.objects.filter(username=username, scan_scanid=scan_id) \
        .update(total_vul=total_vul,
                high_vul=total_high,
                medium_vul=total_medium,
                low_vul=total_low,
                info_vul=total_info,
                total_dup=total_duplicate,
                scan_url=scan_url
                )
    if total_vul == total_duplicate:
        zap_scans_db.objects.filter(username=username, scan_scanid=scan_id) \
            .update(total_vul=total_vul,
                    high_vul=total_high,
                    medium_vul=total_medium,
                    low_vul=total_low,
                    total_dup=total_duplicate
                    )

    subject = 'Archery Tool Scan Status - ZAP Report Uploaded'
    message = 'ZAP Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (target_url, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)