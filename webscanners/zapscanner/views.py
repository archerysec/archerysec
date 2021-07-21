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

import json
import os
import threading
import time
import uuid
from datetime import datetime

from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse

from selenium import webdriver


from archerysettings.models import (ZapSettingsDb, SettingsDb)
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from webscanners.models import (WebScansDb, cookie_db,
                                excluded_db,
                                )
import uuid

setting_file = os.getcwd() + "/" + "apidata.json"

scans_status = None
to_mail = ""
scan_id = None
scan_name = None


def launch_zap_scan(target_url, project_id, rescan_id, rescan, scan_id, user):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    zap_enabled = False
    random_port = "8091"

    all_zap = ZapSettingsDb.objects.filter()
    for zap in all_zap:
        zap_enabled = zap.enabled

    if zap_enabled is False:
        print("started local instence")
        random_port = zap_plugin.zap_local()

        for i in range(0, 100):
            while True:
                try:
                    # Connection Test
                    zap_connect = zap_plugin.zap_connect(random_port)
                    zap_connect.spider.scan(url=target_url)
                except Exception as e:
                    print("ZAP Connection Not Found, re-try after 5 sec")
                    time.sleep(5)
                    continue
                break

    zap_plugin.zap_spider_thread(count=20, random_port=random_port)
    zap_plugin.zap_spider_setOptionMaxDepth(
        count=5, random_port=random_port
    )

    zap_plugin.zap_scan_thread(count=30, random_port=random_port)
    zap_plugin.zap_scan_setOptionHostPerScan(
        count=3, random_port=random_port
    )

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port,
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
        )

        save_all_scan.save()
        notify.send(user, recipient=user, verb="ZAP Scan URL %s Added" % target_url)
    except Exception as e:
        print(e)

    notify.send(user, recipient=user, verb="ZAP Scan Started")
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    notify.send(user, recipient=user, verb="ZAP Scan Spider Completed")
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    zap.zap_scan_status(scan_id=zap_scan_id, un_scanid=scan_id)
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    save_all_vuln = zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        target_url=target_url,
    )
    print(save_all_vuln)
    all_zap_scan = WebScansDb.objects.filter(scanner="zap")

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    if zap_enabled is False:
        zap.zap_shutdown()

    notify.send(user, recipient=user, verb="ZAP Scan URL %s Completed" % target_url)

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )
    email_sch_notify(subject=subject, message=message)


def launch_schudle_zap_scan(target_url, project_id, rescan_id, rescan, scan_id):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    random_port = "8090"

    # Connection Test
    zap_connect = zap_plugin.zap_connect(random_port)

    try:
        zap_connect.spider.scan(url=target_url)

    except Exception:
        subject = "ZAP Connection Not Found"
        message = "ZAP Scanner failed due to setting not found "

        email_sch_notify(subject=subject, message=message)
        print("ZAP Connection Not Found")
        return HttpResponseRedirect(reverse("webscanners:index"))

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
        )

        save_all_scan.save()
    except Exception as e:
        print(e)
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    zap.zap_scan_status(scan_id=zap_scan_id, un_scanid=scan_id)
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        target_url=target_url,
    )
    all_zap_scan = WebScansDb.objects.filter(scanner="zap")

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


def zap_scan(request):
    """
    The function trigger ZAP scan.
    :param request:
    :return:
    """
    global scans_status
    user = request.user
    if request.POST.get(
        "url",
    ):
        target_url = request.POST.get("url")
        project_id = request.POST.get("project_id")
        rescan_id = None
        rescan = "No"
        target_item = str(target_url)
        value = target_item.replace(" ", "")
        target__split = value.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_zap_scan,
                args=(target, project_id, rescan_id, rescan, scan_id, user),
            )
            thread.daemon = True
            thread.start()
            time.sleep(10)
        if scans_status == "100":
            scans_status = "0"
        else:
            return HttpResponse(status=200)
        return HttpResponse(status=200)

    return render(request, "webscanners/zapscanner/zap_scan_list.html")


def zap_settings(request):
    """
    The function calling ZAP Scanner setting page.
    :param request:
    :return:
    """
    zap_api_key = ""
    zap_hosts = None
    zap_ports = None
    zap_enabled = False

    all_zap = ZapSettingsDb.objects.filter()
    for zap in all_zap:
        zap_api_key = zap.zap_api
        zap_hosts = zap.zap_url
        zap_ports = zap.zap_port
        zap_enabled = zap.enabled

    if zap_enabled:
        zap_enabled = "True"
    else:
        zap_enabled = "False"

    return render(
        request,
        "webscanners/zapscanner/zap_settings_form.html",
        {
            "zap_apikey": zap_api_key,
            "zap_host": zap_hosts,
            "zap_port": zap_ports,
            "zap_enabled": zap_enabled,
        },
    )


def zap_setting_update(request):
    """
    The function Update the ZAP settings.
    :param request:
    :return:
    """
    if request.method == "POST":

        all_zap = ZapSettingsDb.objects.filter()
        all_zap.delete()

        all_zap_data = SettingsDb.objects.filter(setting_scanner='Zap')
        all_zap_data.delete()

        if request.POST.get("zap_enabled") == "on":
            zap_enabled = True
        else:
            zap_enabled = False

        apikey = request.POST.get(
            "apikey",
        )
        zaphost = request.POST.get(
            "zappath",
        )
        port = request.POST.get(
            "port",
        )

        setting_id = uuid.uuid4()

        save_zap_data = SettingsDb(
            setting_id=setting_id,
            setting_scanner='Zap',
        )
        save_zap_data.save()

        save_data = ZapSettingsDb(
            setting_id=setting_id,
            zap_url=zaphost,
            zap_port=port,
            zap_api=apikey,
            enabled=zap_enabled,
        )
        save_data.save()

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"
        zap_info = ""

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            zap_info = "Disabled"
            try:
                random_port = zap_plugin.zap_local()
            except:
                return render(request, "setting/settings_page.html", {"zap_info": zap_info})

            for i in range(0, 100):
                while True:
                    try:
                        # Connection Test
                        zap_connect = zap_plugin.zap_connect(
                            random_port
                        )
                        zap_connect.spider.scan(url=target_url)
                    except Exception as e:
                        print("ZAP Connection Not Found, re-try after 5 sec")
                        time.sleep(5)
                        continue
                    break
        else:
            try:
                zap_connect = zap_plugin.zap_connect(random_port,)
                zap_connect.spider.scan(url=target_url)
                zap_info = True
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=zap_info
                )
            except:
                zap_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=zap_info
                )

        return HttpResponseRedirect(reverse("archerysettings:settings"))

    # messages.add_message(request,
    #                      messages.SUCCESS,
    #                      'ZAP Setting Updated ')

    return render(request, "webscanners/zapscanner/zap_settings_form.html")


def slem(driver, url):
    """
    Selenium calling function.
    :param driver:
    :param url:
    :return:
    """
    global new_uri
    new_uri = url
    try:
        driver.get(
            url,
        )
    except Exception as e:
        print("Error Got !!!")
    return


def save_cookie(driver):
    """
    Cookie grabber.
    :param driver:
    :return:
    """
    all_cookies = driver.get_cookies()
    f = open("cookies.txt", "w+")
    for cookie in all_cookies:
        cookie_value = cookie["name"] + "=" + cookie["value"] + ";"
        f.write(cookie_value)
    f.close()
    driver.close()

    return HttpResponseRedirect(reverse("webscanners:index"))


def cookies_list(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_cookies = cookie_db.objects.filter()

    return render(request, "webscanners/cookies_list.html", {"all_cookies": all_cookies})


def del_cookies(request):
    if request.method == "POST":
        cookie_url = request.POST.get("url")
        cookies_item = str(cookie_url)
        cooki_split = cookies_item.replace(" ", "")
        target_split = cooki_split.split(",")
        split_length = target_split.__len__()
        for i in range(0, split_length):
            cookies_target = target_split.__getitem__(i)
            print(cookies_target)
            del_cookie = cookie_db.objects.filter(url=cookies_target)
            del_cookie.delete()
            zap_plugin.zap_replacer(target_url=cookies_target, random_port="8090")
        return HttpResponseRedirect(reverse("webscanners:index"))

    return render(request, "webscanners/cookies_list.html")


def sel_login(request):
    """
    Lgoin perfrom using Selenium.
    :param request:
    :return:
    """
    action_vul = request.POST.get(
        "action",
    )
    url_da = request.POST.get(
        "url_login",
    )
    # print(url_da)
    if action_vul == "open_page":
        global driver
        driver = webdriver.Firefox()
        slem(driver, url_da)
    elif action_vul == "save_cookie":
        save_cookie(driver)
        read_f = open("cookies.txt", "r")

        for cookie_data in read_f:
            # cookie_save.save()
            # target_cookies = request.POST.get('cookies')
            print(cookie_data)
            all_cookie_url = cookie_db.objects.filter(
                Q(url__icontains=new_uri)
            )
            for da in all_cookie_url:
                global cookies
                cookies = da.url

            if cookies == new_uri:
                cookie_db.objects.filter(
                    Q(url__icontains=new_uri)
                ).update(cookie=cookie_data)
                return HttpResponseRedirect(reverse("webscanners:index"))
            else:
                data_dump = cookie_db(
                    url=new_uri, cookie=cookie_data
                )
                data_dump.save()
                return HttpResponseRedirect(reverse("webscanners:index"))
        # messages.add_message(request, messages.SUCCESS, 'Cookies stored')

        return HttpResponseRedirect(reverse("webscanners:index"))
    return render(request, "webscanners/webscanner.html")


def exclude_url(request):
    """
    Excluding URL from scanner. Save excluded URL in Archery Database.
    :param request:
    :return:
    """
    exclud = request.POST.get(
        "exclude_url",
    )
    exclude_save = excluded_db( exclude_url=exclud)
    exclude_save.save()

    return render(
        request,
        "webscanners/webscanner.html",
    )

def exluded_url_list(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_excluded_url = excluded_db.objects.filter()

    if request.method == "POST":
        exclude_url = request.POST.get("exclude_url")
        exluded_item = str(exclude_url)
        exclude_split = exluded_item.replace(" ", "")
        target_split = exclude_split.split(",")
        split_length = target_split.__len__()
        for i in range(0, split_length):
            exclude_target = target_split.__getitem__(i)

            del_excluded = excluded_db.objects.filter(exclude_url=exclude_target
            )
            del_excluded.delete()

        return HttpResponseRedirect(reverse("zapscanner:excluded_url_list"))

    return render(
        request, "webscanners/excludedurl_list.html", {"all_excluded_url": all_excluded_url}
    )

def zap_scan_pdf_gen(request):
    """
    Generate Report in PDF format.
    :param request:
    :return:
    """
    username = request.user.username
    all_scan = WebScansDb.objects.filter( scanner="zap")

    if request.method == "POST":
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")
        vuln_scan = WebScanResultsDb.objects.filter(scan_id=scan_id, scanner="zap"
        )
        zap_all_vul = (
            WebScanResultsDb.objects.filter(scan_id=scan_id, scanner="zap"
            )
            .values("title", "severity", "severity_color", "scan_id")
            .distinct()
        )

        return render_to_pdf_response(
            request,
            template=str("webscanners/zapscanner/zap_scan_pdf_gen.html"),
            download_filename=None,
            content_type="application/pdf",
            context={
                "all_scan": all_scan,
                "vuln_scan": vuln_scan,
                "scan_url": scan_url,
                "zap_all_vul": zap_all_vul,
                # 'evi': evi_list
            },
        )


def export(request):
    """
    :param request:
    :return:
    """

    if request.method == "POST":
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")

        zap_resource = ZapResource()
        queryset = WebScanResultsDb.objects.filter(scan_id__in=value_split
        )
        dataset = zap_resource.export(queryset)
        if report_type.lower() == "csv":
            response = HttpResponse(dataset.csv, content_type="text/csv")
            response["Content-Disposition"] = 'attachment; filename="%s.csv"' % "result"
            return response
        if report_type.lower() == "json":
            response = HttpResponse(dataset.json, content_type="application/json")
            response["Content-Disposition"] = (
                'attachment; filename="%s.json"' % "result"
            )
            return response
        if report_type.lower() == "yaml":
            response = HttpResponse(dataset.yaml, content_type="application/x-yaml")
            response["Content-Disposition"] = (
                'attachment; filename="%s.yaml"' % "result"
            )
            return response
