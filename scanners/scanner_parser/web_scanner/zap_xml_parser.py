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

from webscanners.models import zap_scan_results_db, zap_scans_db
import uuid
import hashlib

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
name = ""
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


def xml_parser(root, project_id, scan_id):
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
        riskcode

    for zap in root:
        host = zap.attrib
        for key, items in host.iteritems():
            if key == "host":
                url = items
        for site in zap:
            for alerts in site:
                for alertsitem in alerts:
                    vuln_id = uuid.uuid4()
                    if alertsitem.tag == "pluginid":
                        pluginid = alertsitem.text
                    if alertsitem.tag == "alert":
                        alert = alertsitem.text
                    if alertsitem.tag == "name":
                        name = alertsitem.text
                    if alertsitem.tag == "riskcode":
                        riskcode = alertsitem.text
                    if alertsitem.tag == "confidence":
                        confidence = alertsitem.text
                    if alertsitem.tag == "desc":
                        desc = alertsitem.text
                    if alertsitem.tag == "solution":
                        solution = alertsitem.text
                    if alertsitem.tag == "reference":
                        reference = alertsitem.text
                    if alertsitem.tag == "wascid":
                        wascid = alertsitem.text
                    if alertsitem.tag == "sourceid":
                        sourceid = alertsitem.text
                    for instances in alertsitem:
                        for instance in instances:
                            instance = instance.text

                    # global riskcode

                    if riskcode == "3":
                        vul_col = "important"
                        risk = "High"
                    elif riskcode == '2':
                        vul_col = "warning"
                        risk = "Medium"
                    elif riskcode == '1':
                        vul_col = "info"
                        risk = "Low"
                    elif riskcode == '0':
                        vul_col = "info"
                        risk = "Informational"

                    dup_data = name + url + risk
                    duplicate_hash = hashlib.sha256(dup_data).hexdigest()
                    match_dup = zap_scan_results_db.objects.filter(
                        dup_hash=duplicate_hash).values('dup_hash').distinct()
                    lenth_match = len(match_dup)

                    if lenth_match == 1:
                        duplicate_vuln = 'Yes'
                    elif lenth_match == 0:
                        duplicate_vuln = 'No'
                    else:
                        duplicate_vuln = 'None'

                    false_p = zap_scan_results_db.objects.filter(
                        false_positive_hash=duplicate_hash)
                    fp_lenth_match = len(false_p)

                    if fp_lenth_match == 1:
                        false_positive = 'Yes'
                    else:
                        false_positive = 'No'

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
                                                    vuln_duplicate=duplicate_vuln
                                                    )
                    dump_data.save()

    zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_id) \
        .values('name', 'risk', 'vuln_color', 'vuln_duplicate').distinct()

    total_vul = len(zap_all_vul)
    total_high = len(zap_all_vul.filter(risk="High"))
    total_medium = len(zap_all_vul.filter(risk="Medium"))
    total_low = len(zap_all_vul.filter(risk="Low"))
    total_duplicate = len(zap_all_vul.filter(vuln_duplicate='Yes'))

    zap_scans_db.objects.filter(scan_scanid=scan_id) \
        .update(total_vul=total_vul,
                high_vul=total_high,
                medium_vul=total_medium,
                low_vul=total_low,
                total_dup=total_duplicate
                )
    if total_vul == total_duplicate:
        zap_scans_db.objects.filter(scan_scanid=scan_id) \
            .update(total_vul=total_vul,
                    high_vul=total_high,
                    medium_vul=total_medium,
                    low_vul=total_low,
                    total_dup=total_duplicate
                    )
