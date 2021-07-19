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

from __future__ import unicode_literals

import codecs
import hashlib
import os
import subprocess
import uuid
from datetime import datetime

import defusedxml.ElementTree as ET
from django.shortcuts import HttpResponseRedirect, render
from django.urls import reverse
from notifications.signals import notify

from scanners.scanner_parser.network_scanner import nmap_parser
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from tools.models import (NiktoResultDb, NiktoVulnDb, NmapResultDb,
                          NmapScanDb, SslscanResultDb)
# NOTE[gmedian]: in order to be more portable we just import everything rather than add anything in this very script
from tools.nmap_vulners.nmap_vulners_view import (nmap_vulners,
                                                  nmap_vulners_port,
                                                  nmap_vulners_scan)

sslscan_output = None
nikto_output = ""
scan_result = ""
all_nmap = ""


def sslscan(request):
    """

    :return:
    """
    global sslscan_output
    all_sslscan = SslscanResultDb.objects.filter()

    user = request.user

    if request.method == "POST":
        scan_url = request.POST.get("scan_url")
        project_id = request.POST.get("project_id")

        scan_item = str(scan_url)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            scan_id = uuid.uuid4()
            scans_url = value_split.__getitem__(i)

            try:
                sslscan_output = subprocess.check_output(
                    ["sslscan", "--no-colour", scans_url]
                )
                notify.send(user, recipient=user, verb="SSLScan Completed")

            except Exception as e:
                print(e)

            dump_scans = SslscanResultDb(
                scan_url=scans_url,
                scan_id=scan_id,
                project_id=project_id,
                sslscan_output=sslscan_output
            )

            dump_scans.save()
            return HttpResponseRedirect(reverse("tools:sslscan"))

    return render(request, "tools/sslscan_list.html", {"all_sslscan": all_sslscan})


def sslscan_result(request):
    """

    :param request:
    :return:
    """

    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        scan_result = SslscanResultDb.objects.filter(
            scan_id=scan_id
        )

    return render(request, "tools/sslscan_result.html", {"scan_result": scan_result})


def sslcan_del(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = SslscanResultDb.objects.filter(scan_id=vuln_id
                                                      )
            del_scan.delete()

    return HttpResponseRedirect(reverse("tools:sslscan"))


def nikto(request):
    """

    :return:
    """
    global nikto_output
    all_nikto = NiktoResultDb.objects.filter()

    user = request.user

    if request.method == "POST":
        scan_url = request.POST.get("scan_url")
        project_id = request.POST.get("project_id")

        scan_item = str(scan_url)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            date_time = datetime.now()
            scan_id = uuid.uuid4()
            scans_url = value_split.__getitem__(i)

            nikto_res_path = os.getcwd() + "/nikto_result/" + str(scan_id) + ".html"

            dump_scans = NiktoResultDb(
                scan_url=scans_url,
                scan_id=scan_id,
                project_id=project_id,
                date_time=date_time,
                nikto_status="Scan Started"
            )

            dump_scans.save()
            HttpResponseRedirect(reverse("tools:nikto"))

            try:

                nikto_output = subprocess.check_output(
                    [
                        "nikto",
                        "-o",
                        nikto_res_path,
                        "-Format",
                        "htm",
                        "-Tuning",
                        "123bde",
                        "-host",
                        scans_url,
                    ]
                )
                f = codecs.open(nikto_res_path, "r")
                data = f.read()
                try:
                    nikto_html_parser(data, project_id, scan_id, )
                    notify.send(user, recipient=user, verb="Nikto Scan Completed")
                    NiktoResultDb.objects.filter(scan_id=scan_id).update(
                        nikto_status="Scan Completed"
                    )
                except Exception as e:
                    print(e)

            except Exception as e:
                print(e)

                try:
                    print("New command running......")
                    print(scans_url)
                    nikto_output = subprocess.check_output(
                        [
                            "nikto.pl",
                            "-o",
                            nikto_res_path,
                            "-Format",
                            "htm",
                            "-Tuning",
                            "123bde",
                            "-host",
                            scans_url,
                        ]
                    )
                    print(nikto_output)
                    f = codecs.open(nikto_res_path, "r")
                    data = f.read()
                    try:
                        nikto_html_parser(data, project_id, scan_id, )
                        notify.send(user, recipient=user, verb="Nikto Scan Completed")
                        NiktoResultDb.objects.filter(scan_id=scan_id).update(
                            nikto_status="Scan Completed"
                        )
                    except Exception as e:
                        print(e)

                except Exception as e:
                    print(e)

    return render(request, "tools/nikto_scan_list.html", {"all_nikto": all_nikto})


def nikto_result(request):
    """

    :param request:
    :return:
    """
    scan_result = ''
    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        scan_result = NiktoResultDb.objects.filter(scan_id=scan_id)

    return render(request, "tools/nikto_scan_result.html", {"scan_result": scan_result})


def nikto_result_vul(request):
    """

    :param request:
    :return:
    """
    scan_id = ''
    if request.method == "GET":
        scan_id = request.GET["scan_id"]

    if request.method == "POST":
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        NiktoVulnDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id
                                   ).update(false_positive=false_positive, vuln_status=status)

        if false_positive == "Yes":
            vuln_info = NiktoVulnDb.objects.filter(scan_id=scan_id, vuln_id=vuln_id
                                                   )
            for vi in vuln_info:
                discription = vi.discription
                hostname = vi.hostname
                dup_data = discription + hostname
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                NiktoVulnDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id
                                           ).update(
                    false_positive=false_positive,
                    vuln_status=status,
                    false_positive_hash=false_positive_hash,
                )
    scan_result = NiktoVulnDb.objects.filter(scan_id=scan_id)

    vuln_data = NiktoVulnDb.objects.filter(

        scan_id=scan_id,
        false_positive="No",
    )

    vuln_data_close = NiktoVulnDb.objects.filter(
         scan_id=scan_id, false_positive="No", vuln_status="Closed"
    )

    false_data = NiktoVulnDb.objects.filter(
         scan_id=scan_id, false_positive="Yes"
    )

    return render(
        request,
        "tools/nikto_vuln_list.html",
        {
            "scan_result": scan_result,
            "vuln_data": vuln_data,
            "vuln_data_close": vuln_data_close,
            "false_data": false_data,
        },
    )


def nikto_vuln_del(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        vuln_id = request.POST.get("del_vuln")
        scan_id = request.POST.get("scan_id")

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            _vuln_id = value_split.__getitem__(i)
            delete_vuln = NiktoVulnDb.objects.filter(
                 vuln_id=_vuln_id
            )
            delete_vuln.delete()

        return HttpResponseRedirect("/tools/nikto_result_vul/?scan_id=%s" % scan_id)


def nikto_scan_del(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()

        for i in range(0, split_length):
            _scan_id = value_split.__getitem__(i)

            del_scan = NiktoResultDb.objects.filter(
                 scan_id=_scan_id
            )
            del_scan.delete()
            del_scan = NiktoVulnDb.objects.filter(scan_id=_scan_id)
            del_scan.delete()

    return HttpResponseRedirect(reverse("tools:nikto"))


def nmap_scan(request):
    """

    :return:
    """
    all_nmap = NmapScanDb.objects.filter()

    return render(request, "tools/nmap_scan.html", {"all_nmap": all_nmap})


def nmap(request):
    """

    :return:
    """
    global all_nmap

    if request.method == "GET":
        ip_address = request.GET["ip"]

        all_nmap = NmapResultDb.objects.filter(
             ip_address=ip_address
        )

    if request.method == "POST":
        ip_address = request.POST.get("ip")
        project_id = request.POST.get("project_id")
        scan_id = uuid.uuid4()

        try:
            print("Start Nmap scan")
            subprocess.check_output(
                [
                    "nmap",
                    "-v",
                    "-sV",
                    "-Pn",
                    "-p",
                    "1-65535",
                    ip_address,
                    "-oX",
                    "output.xml",
                ]
            )

            print("Completed nmap scan")

        except Exception as e:
            print("Eerror in nmap scan:", e)

        try:
            tree = ET.parse("output.xml")
            root_xml = tree.getroot()

            nmap_parser.xml_parser(
                root=root_xml, scan_id=scan_id, project_id=project_id
            )

        except Exception as e:
            print("Error in xml parser:", e)

        return HttpResponseRedirect("/tools/nmap_scan/")

    return render(request, "tools/nmap_list.html", {"all_nmap": all_nmap})


def nmap_result(request):
    """

    :param request:
    :return:
    """
    global scan_result

    if request.method == "GET":
        scan_id = request.GET["scan_id"]
        scan_result = NmapResultDb.objects.filter(scan_id=scan_id)

    return render(request, "tools/nmap_result.html", {"scan_result": scan_result})


def nmap_scan_del(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        ip_address = request.POST.get("ip_address")

        scan_item = str(ip_address)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()

        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)

            del_scan = NmapResultDb.objects.filter(
                 ip_address=vuln_id
            )
            del_scan.delete()
            del_scan = NmapScanDb.objects.filter(scan_ip=vuln_id)
            del_scan.delete()

    return HttpResponseRedirect(reverse("tools:nmap_scan"))
