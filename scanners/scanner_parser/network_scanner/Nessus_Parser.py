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

import datetime
import uuid
from networkscanners.models import nessus_report_db, nessus_scan_db
import hashlib

from webscanners.zapscanner.views import email_sch_notify

agent = "NA"
description = "NA"
fname = "NA"
plugin_modification_date = "NA"
plugin_name = "NA"
plugin_publication_date = "NA"
plugin_type = "NA"
risk_factor = "NA"
script_version = "NA"
see_also = "NA"
solution = "NA"
synopsis = "NA"
plugin_output = "NA"
scan_ip = "NA"
pluginName = "NA"
pluginID = "NA"
protocol = "NA"
severity = "NA"
svc_name = "NA"
pluginFamily = "NA"
port = "NA"
ip = ''
false_positive = None
vuln_color = None
total_vul = 'na'
total_high = 'na'
total_medium = 'na'
total_low = 'na'

def updated_nessus_parser(root, project_id, scan_id, username):
    global agent, description, fname, \
        plugin_modification_date, plugin_name, \
        plugin_publication_date, plugin_type, \
        risk_factor, script_version, solution, \
        synopsis, plugin_output, see_also, scan_ip, \
        pluginName, pluginID, protocol, severity, \
        svc_name, pluginFamily, port, vuln_color, total_vul, total_high, total_medium, total_low

    for data in root:
        for reportHost in data.iter('ReportHost'):
            print("reportHost = " + str(reportHost.attrib))
            try:
                for key, value in reportHost.items():
                    scan_ip = value
                    print("IP = " + str(scan_ip))

            except:
                continue

            scan_status = "100"
            date_time = datetime.datetime.now()
            scan_dump = nessus_scan_db(
                scan_ip=scan_ip,
                scan_id=scan_ip,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
                username=username
            )
            scan_dump.save()

            for ReportItem in reportHost.iter('ReportItem'):
                for key, value in ReportItem.attrib.items():
                    if key == 'pluginName':
                        pluginName = value
                        # print ("pluginName = "+str(value))
                    if key == 'pluginID':
                        pluginID = value
                        # print ("pluginID = "+str(value))
                    if key == 'protocol':
                        protocol = value
                        # print ("protocol = "+str(value))
                    if key == 'severity':
                        severity = value
                        # print ("severity = "+str(value))
                    if key == 'svc_name':
                        svc_name = value
                        # print ("svc_name = "+str(value))
                    if key == 'pluginFamily':
                        pluginFamily = value
                        # print ("pluginFamily = "+str(value))
                    if key == 'port':
                        port = value
                        # print ("port = "+str(value))

                try:
                    agent = ReportItem.find('agent').text
                except:
                    agent = "NA"
                try:
                    description = ReportItem.find('description').text
                except:
                    description = "NA"
                try:
                    fname = ReportItem.find('fname').text
                except:
                    fname = "NA"
                try:
                    plugin_modification_date = ReportItem.find('plugin_modification_date').text
                except:
                    plugin_modification_date = "NA"
                try:
                    plugin_name = ReportItem.find('plugin_name').text
                except:
                    plugin_name = "NA"
                try:
                    plugin_publication_date = ReportItem.find('plugin_publication_date').text
                except:
                    plugin_publication_date = "NA"
                try:
                    plugin_type = ReportItem.find('plugin_type').text
                except:
                    plugin_type = "NA"
                try:
                    risk_factor = ReportItem.find('risk_factor').text
                except:
                    risk_factor = "NA"
                try:
                    script_version = ReportItem.find('script_version').text
                except:
                    script_version = "NA"
                try:
                    see_also = ReportItem.find('see_also').text
                except:
                    see_also = "NA"
                try:
                    solution = ReportItem.find('solution').text
                except:
                    solution = "NA"
                try:
                    synopsis = ReportItem.find('synopsis').text
                except:
                    synopsis = "NA"
                try:
                    plugin_output = ReportItem.find('plugin_output').text
                except:
                    plugin_output = "NA"
                vul_id = uuid.uuid4()


                if risk_factor == 'Critical':
                    vuln_color = 'danger'
                    risk_factor = 'High'
                elif risk_factor == 'High':
                    vuln_color = 'danger'
                    risk_factor = 'High'
                elif risk_factor == 'Medium':
                    vuln_color = 'warning'
                    risk_factor = 'Medium'
                elif risk_factor == 'Low':
                    vuln_color = 'danger'
                    risk_factor = 'Low'
                else:
                    risk_factor = 'Low'
                    vuln_color = 'Low'

                dup_data = scan_ip + plugin_name + severity + port
                duplicate_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                match_dup = nessus_report_db.objects.filter(username=username,
                                                            dup_hash=duplicate_hash).values('dup_hash').distinct()
                lenth_match = len(match_dup)

                if lenth_match == 0:
                    duplicate_vuln = 'No'

                    global false_positive
                    false_p = nessus_report_db.objects.filter(username=username,
                                                              false_positive_hash=duplicate_hash)
                    fp_lenth_match = len(false_p)
                    if fp_lenth_match == 1:
                        false_positive = 'Yes'
                    else:
                        false_positive = 'No'
                    if risk_factor == 'None':
                        risk_factor = 'Informational'
                    all_data_save = nessus_report_db(project_id=project_id,
                                                     scan_id=scan_ip,
                                                     scan_ip=scan_ip,
                                                     vul_id=vul_id,
                                                     agent=agent,
                                                     description=description,
                                                     fname=fname,
                                                     plugin_modification_date=plugin_modification_date,
                                                     plugin_name=plugin_name,
                                                     plugin_publication_date=plugin_publication_date,
                                                     plugin_type=plugin_type,
                                                     risk_factor=risk_factor,
                                                     script_version=script_version,
                                                     see_also=see_also,
                                                     solution=solution,
                                                     synopsis=synopsis,
                                                     plugin_output=plugin_output,
                                                     pluginName=pluginName,
                                                     pluginID=pluginID,
                                                     protocol=protocol,
                                                     severity=severity,
                                                     svc_name=svc_name,
                                                     pluginFamily=pluginFamily,
                                                     port=port,
                                                     false_positive=false_positive,
                                                     vuln_status='Open',
                                                     dup_hash=duplicate_hash,
                                                     vuln_duplicate=duplicate_vuln,
                                                     severity_color=vuln_color,
                                                     username=username,
                                                     )
                    all_data_save.save()
                    print("RESULTS = " + str(all_data_save.scan_id))
                    del_na = nessus_report_db.objects.filter(username=username, plugin_name='NA')
                    del_na.delete()

                    ov_all_vul = nessus_report_db.objects.filter(username=username, scan_id=scan_ip).order_by('scan_ip')
                    total_vul = len(ov_all_vul)
                    total_critical = len(ov_all_vul.filter(risk_factor="Critical"))
                    total_high = len(ov_all_vul.filter(risk_factor="High"))
                    total_medium = len(ov_all_vul.filter(risk_factor="Medium"))
                    total_low = len(ov_all_vul.filter(risk_factor="Low"))
                    total_info = len(ov_all_vul.filter(risk_factor="Informational"))
                    total_duplicate = len(ov_all_vul.filter(vuln_duplicate='Yes'))

                    nessus_scan_db.objects.filter(username=username, scan_id=scan_ip) \
                        .update(total_vul=total_vul,
                                critical_total=total_critical,
                                high_total=total_high,
                                medium_total=total_medium,
                                low_total=total_low,
                                info_total=total_info,
                                total_dup=total_duplicate,
                                scan_ip=scan_ip,
                                )

                else:
                    duplicate_vuln = 'Yes'

                    all_data_save = nessus_report_db(project_id=project_id,
                                                     scan_id=scan_ip,
                                                     scan_ip=scan_ip,
                                                     vul_id=vul_id,
                                                     agent=agent,
                                                     description=description,
                                                     fname=fname,
                                                     plugin_modification_date=plugin_modification_date,
                                                     plugin_name=plugin_name,
                                                     plugin_publication_date=plugin_publication_date,
                                                     plugin_type=plugin_type,
                                                     risk_factor=risk_factor,
                                                     script_version=script_version,
                                                     see_also=see_also,
                                                     solution=solution,
                                                     synopsis=synopsis,
                                                     plugin_output=plugin_output,
                                                     pluginName=pluginName,
                                                     pluginID=pluginID,
                                                     protocol=protocol,
                                                     severity=severity,
                                                     svc_name=svc_name,
                                                     pluginFamily=pluginFamily,
                                                     port=port,
                                                     false_positive='Duplicate',
                                                     vuln_status='Duplicate',
                                                     dup_hash=duplicate_hash,
                                                     vuln_duplicate=duplicate_vuln,
                                                     severity_color=vuln_color,
                                                     username=username,
                                                     )
                    all_data_save.save()
                    ov_all_vul = nessus_report_db.objects.filter(username=username, scan_id=scan_ip)
                    total_duplicate = len(ov_all_vul.filter(vuln_duplicate='Yes'))
                    nessus_scan_db.objects.filter(username=username, scan_id=scan_ip) \
                        .update(

                                total_dup=total_duplicate,
                                scan_ip=scan_ip,
                                )

    subject = 'Archery Tool Scan Status - Nessus Report Uploaded'
    message = 'Nessus Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (scan_id, total_vul, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)
