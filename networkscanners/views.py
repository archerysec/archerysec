# -*- coding: utf-8 -*-
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

""" Author: Anand Tiwari """

from __future__ import unicode_literals

from django.shortcuts import render, render_to_response
from openvas_lib import VulnscanManager, VulnscanException
from networkscanners.models import scan_save_db, ov_scan_result_db
import time
from django.db.models import Q
from django.contrib import messages
from django.http import HttpResponseRedirect
import os
import json
from django.core import signing
import uuid
from projects.models import project_db
import datetime
import xml.etree.ElementTree as ET
import OpenVas_Parser
from archerysettings import save_settings, load_settings

openvas_data = os.getcwd() + '/' + 'apidata.json'

status = ""
name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
page = ""

family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""


def index(request):
    all_ip = scan_save_db.objects.all()

    return render(request, 'index.html', {'all_ip': all_ip})


def scan_status(request):
    if request.method == 'POST':
        all_ip = scan_save_db.objects.all()
        scan_ip = request.POST.get('scan_id', )

    return render(request, 'index.html')


def scan_vul_details(request):
    if request.method == 'GET':
        scan_id = request.GET['scan_id']

    if request.method == 'POST':
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        false_positive = request.POST.get('false')

        ov_scan_result_db.objects.filter(scan_id=scan_id, vul_id=vuln_id).update(false_positive=false_positive)

        return HttpResponseRedirect('/networkscanners/vul_details/?scan_id=%s' % scan_id)

    all_vuln = ov_scan_result_db.objects.filter(scan_id=scan_id, false_positive='No')

    all_false_vul = ov_scan_result_db.objects.filter(scan_id=scan_id, false_positive='Yes')

    return render(request, 'vul_details.html', {'all_vuln': all_vuln, 'scan_id': scan_id,
                                                'all_false_vul': all_false_vul})


def launch_scan(request):
    all_ip = scan_save_db.objects.all()

    if request.method == 'POST':
        all_ip = scan_save_db.objects.all()
        scan_ip = request.POST.get('ip', )
        project_id = request.POST.get('project_id', )
        sel_profile = request.POST.get('scan_profile', )
        Scan_Launch(scan_ip, project_id, sel_profile)

    return render_to_response('vul_details.html', {'all_ip': all_ip})


def Scan_Launch(scan_ip, project_id, sel_profile):

    with open(openvas_data, 'r+') as f:
        data = json.load(f)
        ov_user = data['open_vas_user']
        ov_pass = data['open_vas_pass']
        ov_ip = data['open_vas_ip']

        lod_ov_user = signing.loads(ov_user)
        lod_ov_pass = signing.loads(ov_pass)
        lod_ov_ip = signing.loads(ov_ip)

    scanner = VulnscanManager(str(lod_ov_ip), str(lod_ov_user), str(lod_ov_pass))
    time.sleep(5)
    profile = None
    if profile is None:
        profile = "Full and fast"
    else:
        profile = sel_profile
    scan_id, target_id = scanner.launch_scan(target=str(scan_ip), profile=str(profile))
    date_time = datetime.datetime.now()
    save_all = scan_save_db(scan_id=str(scan_id), project_id=str(project_id), scan_ip=str(scan_ip),
                            target_id=str(target_id), date_time=date_time)
    save_all.save()

    while int(scanner.get_progress(str(scan_id))) < 100.0:
        print 'Scan progress %: ' + str(scanner.get_progress(str(scan_id)))
        status = str(scanner.get_progress(str(scan_id)))
        scan_save_db.objects.filter(scan_id=scan_id).update(scan_status=status)
        time.sleep(5)

    global status
    status = "100"
    scan_save_db.objects.filter(scan_id=scan_id).update(scan_status=status)

    if profile == "Discovery":
        print "returning....."

    else:
        time.sleep(10)
        try:
            openvas_results = scanner.get_raw_xml(str(scan_id))
            vul_an_id(scan_id, openvas_results)
        except Exception as e:
            print e

        try:
            openvas_vul = ov_scan_result_db.objects.filter(scan_id=scan_id).values('name', 'severity', 'vuln_color', 'threat', 'host', 'port').distinct()
            total_vul = len(openvas_vul)
            total_high = len(openvas_vul.filter(threat="High"))
            total_medium = len(openvas_vul.filter(threat="Medium"))
            total_low = len(openvas_vul.filter(threat="Low"))

            scan_save_db.objects.filter(scan_id=scan_id).update(total_vul=total_vul, high_total=total_high,
                                                                medium_total=total_medium, low_total=total_low)
        except Exception as e:
            print e

        try:
            for vul_id in ov_scan_result_db.objects.values_list('vul_id', flat=True).distinct():
                ov_scan_result_db.objects.filter(
                    pk=ov_scan_result_db.objects.filter(vul_id=vul_id).values_list('id', flat=True)[1:]).delete()
        except Exception as e:
            print e


def vul_an_id(scan_id, openvas_results):
    try:
        for d in openvas_results.findall(".//result"):
            for datas, items in d.attrib.viewitems():
                vul_id = items
                print("Vulnerability ID :", vul_id)
                sav_vul_da(vul_id, openvas_results, scan_id)
    except Exception as e:
        print e


def sav_vul_da(vul_id, openvas_results, scan_id):
    print(openvas_results)
    try:
        for data in openvas_results:
            for datas, items in data.attrib.viewitems():
                if items == vul_id:

                    print("-----------------------------------------------------------")
                    print("The vuln is for :", items)

                    for r in data.getchildren():
                        if r.tag == "name":
                            global name
                            if r.text is None:
                                name = "NA"
                            else:
                                name = r.text

                        if r.tag == "creation_time":
                            global creation_time
                            if r.text is None:
                                creation_time = "NA"
                            else:
                                creation_time = r.text

                        if r.tag == "modification_time":
                            global modification_time
                            if r.text is None:
                                modification_time = "NA"
                            else:
                                modification_time = r.text
                        if r.tag == "host":
                            global host
                            if r.text is None:
                                host = "NA"
                            else:
                                host = r.text

                        if r.tag == "port":
                            global port
                            if r.text is None:
                                port = "NA"
                            else:
                                port = r.text
                        if r.tag == "threat":
                            global threat
                            if r.text is None:
                                threat = "NA"
                            else:
                                threat = r.text
                        if r.tag == "severity":
                            global severity
                            if r.text is None:
                                severity = "NA"
                            else:
                                severity = r.text
                        if r.tag == "description":
                            global description
                            if r.text is None:
                                description = "NA"
                            else:
                                description = r.text

                        for rr in r.getchildren():
                            if rr.tag == "family":
                                global family
                                if rr.text is None:
                                    family = "NA"
                                else:
                                    family = rr.text
                            if rr.tag == "cvss_base":
                                global cvss_base
                                if rr.text is None:
                                    cvss_base = "NA"
                                else:
                                    cvss_base = rr.text
                            if rr.tag == "cve":
                                global cve
                                if rr.text is None:
                                    cve = "NA"
                                else:
                                    cve = rr.text
                            if rr.tag == "bid":
                                global bid
                                if rr.text is None:
                                    bid = "NA"
                                else:
                                    bid = rr.text

                            if rr.tag == "xref":
                                global xref
                                if rr.text is None:
                                    xref = "NA"
                                else:
                                    xref = rr.text

                            if rr.tag == "tags":
                                global tags
                                if rr.text is None:
                                    tags = "NA"
                                else:
                                    tags = rr.text
                            if rr.tag == "type":
                                global banner
                                if rr.text is None:
                                    banner = "NA"
                                else:
                                    banner = rr.text

                    date_time = datetime.datetime.now()

                    save_all = ov_scan_result_db(scan_id=scan_id, vul_id=vul_id, name=name,
                                                 creation_time=creation_time, modification_time=modification_time,
                                                 host=host, port=port,
                                                 threat=threat,
                                                 severity=severity,
                                                 description=description,
                                                 family=family, cvss_base=cvss_base, cve=cve,
                                                 bid=bid, xref=xref, tags=tags, banner=banner,
                                                 date_time=date_time, false_positive='No'
                                                 )
                    save_all.save()
    except Exception as e:
        print e


def scan_del(request):
    all_ip = scan_save_db.objects.all()

    if request.method == 'POST':
        scanid = request.POST.get('scan_id')

        scans = scan_save_db.objects.filter(scan_id=scanid).order_by('scan_id')
        scans.delete()

        vuln_data = ov_scan_result_db.objects.filter(scan_id=scanid)
        vuln_data.delete()

    return render_to_response('index.html', {'all_ip': all_ip})


def ip_scan(request):
    all_scans = scan_save_db.objects.all()
    all_proj = project_db.objects.all()

    return render(request, 'ipscan.html', {'all_scans': all_scans, 'all_proj': all_proj})


def ip_scan_table(request):
    all_scans = scan_save_db.objects.all()

    return render(request, 'ip_scan_table.html', {'all_scans': all_scans})


def openvas_details(request):

    # Load OpenVAS setting from archerysetting function
    save_openvas_setting = save_settings.SaveSettings(openvas_data)

    if request.method == 'POST':
        openvas_host = request.POST.get("scan_host", )
        openvas_user = request.POST.get("openvas_user", )
        openvas_password = request.POST.get("openvas_password", )

        save_openvas_setting.openvas_settings(
            ipaddress=openvas_host,
            openvas_user=openvas_user,
            openvas_password=openvas_password,
        )

    messages.add_message(request, messages.SUCCESS, 'Openvas Setting Updated ')

    return render(request, 'setting_form.html', )


def openvas_setting(request):
    return render(request, 'setting_form.html', )


def del_vuln(request):
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        delete_vuln = ov_scan_result_db.objects.filter(vul_id=vuln_id)
        delete_vuln.delete()

        ov_all_vul = ov_scan_result_db.objects.filter(scan_id=un_scanid).order_by('scan_id')
        total_vul = len(ov_all_vul)
        total_high = len(ov_all_vul.filter(threat="High"))
        total_medium = len(ov_all_vul.filter(threat="Medium"))
        total_low = len(ov_all_vul.filter(threat="Low"))

        scan_save_db.objects.filter(scan_id=un_scanid).update(total_vul=total_vul, high_total=total_high,
                                                              medium_total=total_medium, low_total=total_low)
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/networkscanners/vul_details/?scan_id=%s" % un_scanid)


def edit_vuln(request):
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id", )
        vul_id = request.POST.get("vuln_id", )

        name = request.POST.get("name", )
        creation_time = request.POST.get("creation_time", )
        modification_time = request.POST.get("modification_time", )
        host = request.POST.get("host", )
        port = request.POST.get("port", )
        threat = request.POST.get("threat", )
        severity = request.POST.get("severity", )
        description = request.POST.get("description", )
        family = request.POST.get("family", )
        cvss_base = request.POST.get("cvss_base", )
        cve = request.POST.get("cve", )
        # bid = request.POST.get("bid")
        xref = request.POST.get("xref", )
        tags = request.POST.get("tags", )
        banner = request.POST.get("banner", )

        print "edit_vul :", name

        ov_scan_result_db.objects.filter(vul_id=vul_id).update(name=name,
                                                               creation_time=creation_time,
                                                               modification_time=modification_time,
                                                               host=host, port=port,
                                                               threat=threat,
                                                               severity=severity,
                                                               description=description, family=family,
                                                               cvss_base=cvss_base, cve=cve,
                                                               xref=xref, tags=tags, banner=banner)

        messages.success(request, "Vulnerability Edited")

        return HttpResponseRedirect("/networkscanners/vul_details/?scan_id=%s" % scan_id)

    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    edit_vul_dat = ov_scan_result_db.objects.filter(vul_id=id_vul).order_by('vul_id')

    return render(request, 'ov_edit_vuln_data.html', {'edit_vul_dat': edit_vul_dat})


def vuln_check(request):
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    vul_dat = ov_scan_result_db.objects.filter(vul_id=id_vul).order_by('vul_id')

    return render(request, 'ov_vuln_data.html', {'vul_dat': vul_dat})


def add_vuln(request):
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = ''

    print "scan_id :----------", scan_id

    if request.method == 'POST':
        vuln_id = uuid.uuid4()
        scan_id = request.POST.get("scan_id", )
        name = request.POST.get("name", )
        creation_time = request.POST.get("creation_time", )
        modification_time = request.POST.get("modification_time", )
        host = request.POST.get("host", )
        port = request.POST.get("port", )
        threat = request.POST.get("threat", )
        severity = request.POST.get("severity", )
        description = request.POST.get("description", )
        family = request.POST.get("family", )
        cvss_base = request.POST.get("cvss_base", )
        cve = request.POST.get("cve", )
        # bid = request.POST.get("bid")
        xref = request.POST.get("xref", )
        tags = request.POST.get("tags", )
        banner = request.POST.get("banner", )

        save_vuln = ov_scan_result_db(name=name, vul_id=vuln_id, scan_id=scan_id,
                                      creation_time=creation_time,
                                      modification_time=modification_time,
                                      host=host, port=port,
                                      threat=threat,
                                      severity=severity,
                                      description=description, family=family,
                                      cvss_base=cvss_base, cve=cve,
                                      xref=xref, tags=tags, banner=banner)
        save_vuln.save()

        messages.success(request, "Vulnerability Added")
        return HttpResponseRedirect("/networkscanners/vul_details/?scan_id=%s" % scan_id)

    return render(request, 'ov_add_vuln.html', {'scan_id': scan_id})


def OpenVas_xml_upload(request):
    all_project = project_db.objects.all()
    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES['xmlfile']
        scan_ip = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "openvas":
            date_time = datetime.datetime.now()
            scan_dump = scan_save_db(scan_ip=scan_ip, scan_id=scan_id, date_time=date_time,
                                     project_id=project_id, scan_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            OpenVas_Parser.xml_parser(project_id=project_id, scan_id=scan_id, root=root_xml)
            return HttpResponseRedirect("/networkscanners/")

    return render(request, 'net_upload_xml.html', {'all_project': all_project})