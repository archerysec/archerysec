# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, render_to_response
from openvas_lib import VulnscanManager, VulnscanException
from networkscanners.models import scan_save_db, ov_scan_result_db, openvas_info
import time
from django.db.models import Q
from django.contrib import messages
from django.http import HttpResponseRedirect

openvas = openvas_info.objects.all()

for dat in openvas:
    scan_host = str(dat.openvas_host)
    user = str(dat.openvas_user)
    password = str(dat.openvas_password)

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
        scan_ip = request.POST.get('scan_id')

    return render(request, 'index.html')


def scan_vul_details(request):
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = ''

    all_vuln = ov_scan_result_db.objects.filter(scan_id=scan_id).order_by('scan_id')

    # all_vul_data = ov_scan_result_db.objects.all()

    return render(request, 'vul_details.html', {'all_vuln': all_vuln})


def launch_scan(request):
    all_ip = scan_save_db.objects.all()

    scanner = VulnscanManager(scan_host, user, password)
    time.sleep(5)
    if request.method == 'POST':
        all_ip = scan_save_db.objects.all()
        scan_ip = request.POST.get('ip')
        profile = None
        if profile is None:
            profile = "Full and fast"
        else:
            profile = request.POST.get('scan_profile')
        scan_id, target_id = scanner.launch_scan(target=str(scan_ip), profile=str(profile))
        save_all = scan_save_db(scan_id=str(scan_id), scan_ip=str(scan_ip), target_id=str(target_id))
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
                openvas_vul = ov_scan_result_db.objects.filter(Q(scan_id=scan_id)).order_by('scan_id')
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

    return render_to_response('vul_details.html', {'all_ip': all_ip})


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

                    save_all = ov_scan_result_db(scan_id=scan_id, vul_id=vul_id, name=name,
                                                 creation_time=creation_time, modification_time=modification_time,
                                                 host=host, port=port,
                                                 threat=threat,
                                                 severity=severity,
                                                 description=description, family=family, cvss_base=cvss_base, cve=cve,
                                                 bid=bid, xref=xref, tags=tags, banner=banner)
                    save_all.save()
    except Exception as e:
        print e


def scan_del(request):
    all_ip = scan_save_db.objects.all()

    if request.method == 'GET':
        scanid = request.GET['scan_scanid']

        scans = scan_save_db.objects.filter(Q(scan_id=scanid)).order_by('scan_id')
        scans.delete()

    return render_to_response('index.html', {'all_ip': all_ip})


def ip_scan(request):
    all_scans = scan_save_db.objects.all()

    return render(request, 'ipscan.html', {'all_scans': all_scans})


def ip_scan_table(request):
    all_scans = scan_save_db.objects.all()

    return render(request, 'ip_scan_table.html', {'all_scans': all_scans})


def openvas_details(request):
    if request.method == 'POST':
        scan_host = request.POST.get("scan_host")
        openvas_user = request.POST.get("openvas_user")
        openvas_password = request.POST.get("openvas_password")

        delete_all = openvas_info.objects.all()
        delete_all.delete()
        #
        dump_all = openvas_info(openvas_host=scan_host, openvas_user=openvas_user, openvas_password=openvas_password)
        dump_all.save()

    return render(request, 'setting_form.html', )


def openvas_setting(request):
    return render(request, 'setting_form.html', )


def del_vuln(request):
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln")
        un_scanid = request.POST.get("scan_id")
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
        scan_id = request.POST.get("scan_id")
        vul_id = request.POST.get("vuln_id")

        name = request.POST.get("name")
        creation_time = request.POST.get("creation_time")
        modification_time = request.POST.get("modification_time")
        host = request.POST.get("host")
        port = request.POST.get("port")
        threat = request.POST.get("threat")
        severity = request.POST.get("severity")
        description = request.POST.get("description")
        family = request.POST.get("family")
        cvss_base = request.POST.get("cvss_base")
        cve = request.POST.get("cve")
        # bid = request.POST.get("bid")
        xref = request.POST.get("xref")
        tags = request.POST.get("tags")
        banner = request.POST.get("banner")

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
