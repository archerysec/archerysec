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

import json
import os
import threading
import time
import uuid
from datetime import datetime

import defusedxml.ElementTree as ET
from background_task import background
from background_task.models import Task
from django.contrib import auth, messages
from django.contrib.auth.models import User
from django.core import signing
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from jira import JIRA
from lxml import etree
from notifications.models import Notification
from PyBurprestapi import burpscanner
from selenium import webdriver
from stronghold.decorators import public

import PyArachniapi
from archerysettings import load_settings
from archerysettings.models import (ArachniSettingsDb,
                                    EmailDb, NmapVulnersSettingDb,
                                    ZapSettingsDb, SettingsDb)
from jiraticketing.models import jirasetting
from projects.models import ProjectDb
from scanners.scanner_parser.staticscanner_parser import (
    checkmarx_xml_report_parser, dependencycheck_report_parser,
    findbugs_report_parser)
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from scanners.scanner_parser.web_scanner import (acunetix_xml_parser,
                                                 arachni_xml_parser,
                                                 burp_xml_parser,
                                                 netsparker_xml_parser,
                                                 webinspect_xml_parser,
                                                 zap_xml_parser)
from scanners.scanner_plugin.network_scanner.openvas_plugin import \
    OpenVAS_Plugin
from scanners.scanner_plugin.web_scanner import burp_plugin, zap_plugin
from staticscanners.models import (StaticScansDb)
from tools.models import NiktoResultDb
from webscanners.models import (WebScansDb, cookie_db,
                                excluded_db,
                                task_schedule_db)
from webscanners.zapscanner.views import launch_schudle_zap_scan
import uuid

setting_file = os.getcwd() + "/" + "apidata.json"

# All global variable
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
alert = ""
project_id = None
# target_url = None
scan_ip = None
# burp_status = 0
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
# vuln_id = ""
methods = ""
dec_res = ""
dec_req = ""
decd_req = ""
scanner = ""
all_scan_url = ""
all_url_vuln = ""
zap_apikey = None
zap_host = None
zap_port = None


# Login View
@public
@csrf_protect
def login(request):
    """
    Login Request
    :param request:
    :return:
    """
    c = {}
    c.update(request)
    return render(request, "login/login.html", c)


@public
def auth_view(request):
    """
    Authentication request.
    :param request:
    :return:
    """
    username = request.POST.get(
        "username",
        "",
    )
    password = request.POST.get(
        "password",
        "",
    )
    user = auth.authenticate(username=username, password=password)

    if user is not None:
        auth.login(request, user)
        return HttpResponseRedirect(reverse("dashboard:dashboard"))
    else:
        messages.add_message(
            request, messages.ERROR, "Please check your login details and try again."
        )
        return HttpResponseRedirect(reverse("webscanners:login"))


@public
def logout(request):
    """
    Logout request
    :param request:
    :return:
    """
    auth.logout(request)
    return render(request, "logout/logout.html")


@public
def signup(request):
    """
    Signup Request.
    :param request:
    :return:
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        email = request.POST.get("email")
        user_c = User.objects.filter(username=username)
        if user_c:
            messages.add_message(request, messages.ERROR, "User already exists")
            return HttpResponseRedirect(reverse("webscanners:signup"))
        else:
            user = User.objects.create_user(username, email, password)
            user.save()
        return HttpResponseRedirect(reverse("webscanners:login"))

    return render(request, "signup/signup.html")


def error_404_view(request):
    return render(request, "error/404.html")


def loggedin(request):
    """
    After login request.
    :param request:
    :return:
    """
    return render(request, "webscanners/webscanner.html")


def del_notify(request):
    """

    :return:
    """
    if request.method == "GET":
        notify_id = request.GET["notify_id"]

        notify_del = Notification.objects.filter(id=notify_id)
        notify_del.delete()

    return HttpResponseRedirect(reverse("dashboard:dashboard"))


def del_all_notify(request):
    """

    :return:
    """
    if request.method == "GET":
        notify_del = Notification.objects.all()
        notify_del.delete()

    return HttpResponseRedirect(reverse("dashboard:dashboard"))


def index(request):
    """
    The function calling web scan Page.
    :param request:
    :return:
    """
    all_scans = WebScansDb.objects.filter()
    all_excluded_url = excluded_db.objects.filter()
    all_cookies = cookie_db.objects.filter()

    all_scans_db = ProjectDb.objects.filter()

    all_notify = Notification.objects.unread()

    return render(
        request,
        "webscanners/webscanner.html",
        {
            "spider_status": spider_status,
            "scans_status": scans_status,
            "all_scans": all_scans,
            "spider_alert": spider_alert,
            "all_excluded_url": all_excluded_url,
            "all_cookies": all_cookies,
            "all_scans_db": all_scans_db,
            "message": all_notify,
        },
    )


@background(schedule=60)
def task(target_url, project_id, scanner, **kwargs):
    rescan_id = ''
    rescan = 'No'
    target__split = target_url.split(',')
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        # noinspection PyInterpreter
        if scanner == "zap_scan":
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_schudle_zap_scan,
                args=(target, project_id, rescan_id, rescan, scan_id, kwargs["username"]))
            thread.daemon = True
            thread.start()
        elif scanner == "burp_scan":
            scan_id = uuid.uuid4()
            do_scan = burp_plugin.burp_scans(
                project_id,
                target,
                scan_id, user=kwargs["username"])
            thread = threading.Thread(
                target=do_scan.scan_launch,
            )
            thread.daemon = True
            thread.start()

        return HttpResponse(status=200)


def web_task_launch(request):
    if request.method == "GET":
        task_time = request.GET["time"]

        t = Task.objects.all()
        # t.delete()
        print(task_time)

        for ta in t:
            print(ta.run_at)
            print(ta.id)

    return HttpResponse(status=200)


def web_scan_schedule(request):
    """

    :param request:
    :return:
    """
    all_scans_db = ProjectDb.objects.filter()
    all_scheduled_scans = task_schedule_db.objects.filter()

    if request.method == "POST":
        scan_url = request.POST.get("url")
        scan_schedule_time = request.POST.get("datetime")
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        # periodic_task = request.POST.get('periodic_task')
        periodic_task_value = request.POST.get("periodic_task_value")
        # periodic_task = 'Yes'
        if periodic_task_value == "HOURLY":
            periodic_time = Task.HOURLY
        elif periodic_task_value == "DAILY":
            periodic_time = Task.DAILY
        elif periodic_task_value == "WEEKLY":
            periodic_time = Task.WEEKLY
        elif periodic_task_value == "EVERY_2_WEEKS":
            periodic_time = Task.EVERY_2_WEEKS
        elif periodic_task_value == "EVERY_4_WEEKS":
            periodic_time = Task.EVERY_4_WEEKS
        else:
            periodic_time = None
        dt_str = scan_schedule_time
        dt_obj = datetime.strptime(dt_str, "%d/%m/%Y %H:%M:%S %p")
        target__split = scan_url.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)

            if scanner == 'zap_scan':
                if periodic_task_value == 'None':
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
                else:

                    my_task = task(target, project_id, scanner, repeat=periodic_time, repeat_until=None)
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
            elif scanner == 'burp_scan':
                if periodic_task_value == 'None':
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                else:
                    my_task = task(
                        target,
                        project_id,
                        scanner,
                        repeat=periodic_time,
                        repeat_until=None,
                    )
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
            save_scheadule = task_schedule_db(
                task_id=task_id,
                target=target,
                schedule_time=scan_schedule_time,
                project_id=project_id,
                scanner=scanner,
                periodic_task=periodic_task_value,
            )
            save_scheadule.save()

    return render(
        request,
        "webscanners/web_scan_schedule.html",
        {"all_scans_db": all_scans_db, "all_scheduled_scans": all_scheduled_scans},
    )


def del_web_scan_schedule(request):
    """

    :param request:
    :return:
    """
    if request.method == "POST":
        task_id = request.POST.get("task_id")

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(",")
        split_length = target_split.__len__()
        print("split_length", split_length)
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = task_schedule_db.objects.filter(
                task_id=task_id
            )
            del_task.delete()
            del_task_schedule = Task.objects.filter(id=task_id)
            del_task_schedule.delete()

    return HttpResponseRedirect(reverse("webscanners:web_scan_schedule"))


def burp_scan_launch(request):
    """
    Burp Scan Trigger.
    :param request:
    :return:
    """
    user = request.user
    if request.POST.get("url"):
        target_url = request.POST.get("url")
        project_id = request.POST.get("project_id")
        target__split = target_url.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print("Targets", target)
            scan_id = uuid.uuid4()
            date_time = datetime.now()
            scan_dump = WebScansDb(
                scan_id=scan_id,
                project_id=project_id,
                url=target,
                date_time=date_time,
                scanner='Burp'
            )
            scan_dump.save()
            try:
                do_scan = burp_plugin.burp_scans(project_id, target, scan_id, user)
                # do_scan.scan_lauch(project_id,
                #                    target,
                #                    scan_id)

                thread = threading.Thread(
                    target=do_scan.scan_launch,
                )
                thread.daemon = True
                thread.start()
                time.sleep(5)
            except Exception as e:
                print(e)

    return render(request, "webscanners/scans/list_scans.html")


def xml_upload(request):
    """
    Handling XML upload files.
    :param request:
    :return:
    """
    all_project = ProjectDb.objects.filter()

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES["xmlfile"]
        scan_url = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "zap_scan":
            try:
                tree = ET.parse(xml_file)
                date_time = datetime.now()

                root_xml = tree.getroot()
                en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                    "ascii", "ignore"
                )
                root_xml_en = ET.fromstring(en_root_xml)
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    rescan="No",
                    scanner="Zap",
                )
                scan_dump.save()
                zap_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml_en,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "burp_scan":
            try:
                date_time = datetime.now()
                # Burp scan XML parser
                tree = ET.parse(xml_file)
                root_xml = tree.getroot()
                en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                    "ascii", "ignore"
                )
                root_xml_en = ET.fromstring(en_root_xml)
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner='Burp'
                )
                scan_dump.save()
                burp_xml_parser.burp_scan_data(
                    root_xml_en, project_id, scan_id
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "arachni":
            try:
                date_time = datetime.now()

                tree = ET.parse(xml_file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner='Arachni'
                )
                scan_dump.save()
                arachni_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                    target_url=scan_url,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("webscanners:list_scans"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "netsparker":
            try:
                date_time = datetime.now()

                tree = ET.parse(xml_file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner='Netsparker'
                )
                scan_dump.save()
                netsparker_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(
                    reverse("webscanners:list_scans")
                )
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})
        elif scanner == "webinspect":
            try:
                date_time = datetime.now()

                tree = ET.parse(xml_file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner='Webinspect',
                )
                scan_dump.save()
                webinspect_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(
                    reverse("webscanners:list_scans")
                )
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "acunetix":
            try:
                date_time = datetime.now()

                tree = ET.parse(xml_file)
                root_xml = tree.getroot()
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scanner='Acunetix',
                    scan_status=scan_status,
                )
                scan_dump.save()
                acunetix_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=scan_id,
                    root=root_xml,
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(
                    reverse("webscanners:list_scans")
                )
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "dependencycheck":
            try:
                date_time = datetime.now()

                data = etree.parse(xml_file)
                root = data.getroot()
                scan_dump = StaticScansDb(
                    project_name=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner='Dependencycheck'
                )
                scan_dump.save()
                dependencycheck_report_parser.xml_parser(
                    project_id=project_id, scan_id=scan_id, data=root
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(
                    reverse("dependencycheck:dependencycheck_list")
                )
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "checkmarx":
            try:
                date_time = datetime.now()

                data = etree.parse(xml_file)
                root = data.getroot()
                scan_dump = StaticScansDb(
                    project_name=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status
                )
                scan_dump.save()
                checkmarx_xml_report_parser.checkmarx_report_xml(
                    project_id=project_id, scan_id=scan_id, data=root
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("checkmarx:checkmarx_list"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "findbugs":
            try:
                date_time = datetime.now()

                tree = ET.parse(xml_file)
                root = tree.getroot()
                scan_dump = StaticScansDb(
                    project_name=scan_url,
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status
                )
                scan_dump.save()
                findbugs_report_parser.xml_parser(
                    project_id=project_id, scan_id=scan_id, root=root
                )
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("findbugs:findbugs_list"))
            except Exception as e:
                print(e)
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

        elif scanner == "nikto":
            try:
                date_time = datetime.now()
                scan_dump = NiktoResultDb(
                    date_time=date_time,
                    scan_url=scan_url,
                    scan_id=scan_id,
                    project_id=project_id,
                )
                scan_dump.save()

                nikto_html_parser(xml_file, project_id, scan_id)
                messages.success(request, "File Uploaded")
                return HttpResponseRedirect(reverse("tools:nikto"))
            except:
                messages.error(request, "File Not Supported")
                return render(request, "webscanners/upload_xml.html", {"all_project": all_project})

    return render(request, "webscanners/upload_xml.html", {"all_project": all_project})


def add_cookies(request):
    """
    Cookies storing into Archery Database.
    :param request:
    :return:
    """
    if request.method == "POST":
        target_url = request.POST.get("url")
        target_cookies = request.POST.get("cookies")
        all_cookie_url = cookie_db.objects.filter(
            Q(url__icontains=target_url)
        )
        for da in all_cookie_url:
            global cookies
            cookies = da.url

        if cookies == target_url:
            cookie_db.objects.filter(
                Q(url__icontains=target_url)
            ).update(cookie=target_cookies)
            return HttpResponseRedirect(reverse("webscanners:index"))
        else:
            data_dump = cookie_db(
                url=target_url, cookie=target_cookies
            )
            data_dump.save()
            return HttpResponseRedirect(reverse("webscanners:index"))

    return render(request, "webscanners/cookie_add.html")


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
    all_cookies = cookie_db.objects.filter()

    return render(request, "webscanners/cookies_list.html", {"all_cookies": all_cookies})


def del_cookies(request):
    if request.method == "POST":
        cookie_url = request.POST.get("url")
        cookies_item = str(cookie_url)
        cooki_split = cookies_item.replace(" ", "")
        target_split = cooki_split.split(",")
        split_length = target_split.__len__()
        print("split_length", split_length)
        for i in range(0, split_length):
            cookies_target = target_split.__getitem__(i)
            print(cookies_target)
            del_cookie = cookie_db.objects.filter(url=cookies_target)
            del_cookie.delete()
            zap_plugin.zap_replacer(target_url=cookies_target, random_port='8883')
        return HttpResponseRedirect(reverse("webscanners:cookies_list"))

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
    if action_vul == "open_page":
        global driver
        driver = webdriver.Firefox()
        slem(driver, url_da)
    elif action_vul == "save_cookie":
        save_cookie(driver)
        read_f = open("cookies.txt", "r")

        for cookie_data in read_f:

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
                    url=new_uri,
                    cookie=cookie_data,
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
    exclude_save = excluded_db(exclude_url=exclud)
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
