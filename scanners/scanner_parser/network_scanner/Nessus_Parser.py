#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
#/_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

import xml.etree.ElementTree as ET

import datetime
import uuid
from networkscanners.models import nessus_report_db, nessus_scan_db
import hashlib

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


def nessus_parser(root, project_id, scan_id):
    """
    The function is for parser of Nessus scan file as .nessus.
    :param root:
    :param project_id:
    :param scan_id:
    :return:
    """

    global agent, description, fname,\
        plugin_modification_date, plugin_name,\
        plugin_publication_date, plugin_type,\
        risk_factor, script_version, solution,\
        synopsis, plugin_output, see_also, scan_ip, \
        pluginName, pluginID, protocol, severity,\
        svc_name, pluginFamily, port
    for data in root:
        for report in data:
            if report.tag == 'ReportHost':
                global ip
                ip = report.attrib
    for key, value in ip.viewitems():
        scan_ip = value

    for data in root:
        for report in data:
            for reportHost in report:
                report_attrib = reportHost.attrib
                for key, values in report_attrib.viewitems():
                    if key == 'pluginName':
                        pluginName = values
                    if key == 'pluginID':
                        pluginID = values
                    if key == 'protocol':
                        protocol = values
                    if key == 'severity':
                        severity = values
                    if key == 'svc_name':
                        svc_name = values
                    if key == 'pluginFamily':
                        pluginFamily = values
                    if key == 'port':
                        port = values
                for ReportItem in reportHost:
                    if ReportItem.tag == 'agent':
                        if ReportItem.text is None:
                            agent = "NA"
                        else:
                            agent = ReportItem.text
                    if ReportItem.tag == 'description':
                        if ReportItem.text is None:
                            description = "NA"
                        else:
                            description = ReportItem.text
                    if ReportItem.tag == 'fname':
                        if ReportItem.text is None:
                            fname = "NA"
                        else:
                            fname = ReportItem.text
                    if ReportItem.tag == 'plugin_modification_date':
                        if ReportItem.text is None:
                            plugin_modification_date = "NA"
                        else:
                            plugin_modification_date = ReportItem.text
                    if ReportItem.tag == 'plugin_name':
                        if ReportItem.text is None:
                            plugin_name = "NA"
                        else:
                            plugin_name = ReportItem.text
                    if ReportItem.tag == 'plugin_publication_date':
                        if ReportItem.text is None:
                            plugin_publication_date = "NA"
                        else:
                            plugin_publication_date = ReportItem.text
                    if ReportItem.tag == 'plugin_type':
                        if ReportItem.text is None:
                            plugin_type = "NA"
                        else:
                            plugin_type = ReportItem.text
                    if ReportItem.tag == 'risk_factor':
                        if ReportItem.text is None:
                            risk_factor = "NA"
                        else:
                            risk_factor = ReportItem.text
                    if ReportItem.tag == 'script_version':
                        if ReportItem.text is None:
                            script_version = "NA"
                        else:
                            script_version = ReportItem.text
                    if ReportItem.tag == 'see_also':
                        if ReportItem.text is None:
                            see_also = "NA"
                        else:
                            see_also = ReportItem.text
                    if ReportItem.tag == 'solution':
                        if ReportItem.text is None:
                            solution = "NA"
                        else:
                            solution = ReportItem.text
                    if ReportItem.tag == 'synopsis':
                        if ReportItem.text is None:
                            synopsis = "NA"
                        else:
                            synopsis = ReportItem.text
                    if ReportItem.tag == 'plugin_output':
                        if ReportItem.text is None:
                            plugin_output = "NA"
                        else:
                            plugin_output = ReportItem.text

                vul_id = uuid.uuid4()

                dup_data = scan_ip + plugin_name + severity + port
                duplicate_hash = hashlib.sha1(dup_data).hexdigest()

                match_dup = nessus_report_db.objects.filter(
                    dup_hash=duplicate_hash).values('dup_hash').distinct()
                lenth_match = len(match_dup)

                if lenth_match == 1:
                    duplicate_vuln = 'Yes'
                elif lenth_match == 0:
                    duplicate_vuln = 'No'
                else:
                    duplicate_vuln = 'None'

                global false_positive
                false_p = nessus_report_db.objects.filter(
                    false_positive_hash=duplicate_hash)
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = 'Yes'
                else:
                    false_positive = 'No'

                all_data_save = nessus_report_db(project_id=project_id,
                                                 scan_id=scan_id,
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
                                                 vuln_duplicate=duplicate_vuln
                                                 )
                all_data_save.save()

                del_na = nessus_report_db.objects.filter(plugin_name='NA')
                del_na.delete()

                ov_all_vul = nessus_report_db.objects.filter(scan_id=scan_id).order_by('scan_id')
                total_vul = len(ov_all_vul)
                total_critical = len(ov_all_vul.filter(risk_factor="Critical"))
                total_high = len(ov_all_vul.filter(risk_factor="High"))
                total_medium = len(ov_all_vul.filter(risk_factor="Medium"))
                total_low = len(ov_all_vul.filter(risk_factor="Low"))
                total_duplicate = len(ov_all_vul.filter(vuln_duplicate='Yes'))

                nessus_scan_db.objects.filter(scan_id=scan_id) \
                    .update(total_vul=total_vul,
                            critical_total=total_critical,
                            high_total=total_high,
                            medium_total=total_medium,
                            low_total=total_low,
                            total_dup=total_duplicate,
                            )
                if total_vul == total_duplicate:
                    nessus_scan_db.objects.filter(scan_id=scan_id) \
                        .update(total_vul='0',
                                critical_total='0',
                                high_total='0',
                                medium_total='0',
                                low_total='0',
                                total_dup=total_duplicate,
                                )
