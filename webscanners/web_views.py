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

import threading
import time
import uuid
import defusedxml.ElementTree as ET
from django.contrib import auth
from django.contrib import messages
from django.contrib.auth.models import User
from django.core import signing
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import render,  HttpResponse
from django.views.decorators.csrf import csrf_protect
from selenium import webdriver
from stronghold.decorators import public
from archerysettings import load_settings, save_settings
from projects.models import project_db
from scanners.scanner_parser.web_scanner import zap_xml_parser, \
    arachni_xml_parser, netsparker_xml_parser, webinspect_xml_parser, acunetix_xml_parser, burp_xml_parser
# from scanners.scanner_plugin.web_scanner import burp_plugin
from scanners.scanner_plugin.web_scanner import zap_plugin, burp_plugin
from webscanners.models import \
    zap_scans_db, \
    zap_spider_db, \
    zap_spider_results, \
    cookie_db, excluded_db, \
    burp_scan_db, \
    arachni_scan_db, \
    task_schedule_db, \
    acunetix_scan_db
from background_task import background
from datetime import datetime
from background_task.models import Task
import os
from jiraticketing.models import jirasetting
from webscanners.models import netsparker_scan_db, \
    webinspect_scan_db
from webscanners.zapscanner.views import launch_schudle_zap_scan
from archerysettings.models import zap_settings_db, \
    burp_setting_db, \
    nmap_vulners_setting_db, \
    arachni_settings_db, email_db
from scanners.scanner_parser.staticscanner_parser import dependencycheck_report_parser, findbugs_report_parser, \
    checkmarx_xml_report_parser
from lxml import etree
from staticscanners.models import dependencycheck_scan_db, \
    findbugs_scan_db, checkmarx_scan_results_db, checkmarx_scan_db
from tools.models import nikto_result_db
import codecs
from scanners.scanner_parser.tools.nikto_htm_parser import nikto_html_parser
from notifications.models import Notification
from django.urls import reverse

setting_file = os.getcwd() + '/' + 'apidata.json'

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
    return render(request, "login.html", c)


@public
def auth_view(request):
    """
    Authentication request.
    :param request:
    :return:
    """
    username = request.POST.get('username', '', )
    password = request.POST.get('password', '', )
    user = auth.authenticate(username=username, password=password)

    if user is not None:
        auth.login(request, user)
        return HttpResponseRedirect(reverse('dashboard:dashboard'))
    else:
        messages.add_message(request, messages.ERROR, 'Please check your login details and try again.')
        return HttpResponseRedirect(reverse('webscanners:login'))


@public
def logout(request):
    """
    Logout request
    :param request:
    :return:
    """
    auth.logout(request)
    return render(request, 'logout.html')


@public
def signup(request):
    """
    Signup Request.
    :param request:
    :return:
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        user_c = User.objects.filter(username=username)
        if user_c:
            messages.add_message(request, messages.ERROR, 'User already exists')
            return HttpResponseRedirect(reverse('webscanners:signup'))
        else:
            user = User.objects.create_user(username, email, password)
            user.save()
        return HttpResponseRedirect(reverse('webscanners:login'))

    return render(request, 'signup.html')


def error_404_view(request):
    return render(request, '404.html')


def loggedin(request):
    """
    After login request.
    :param request:
    :return:
    """
    return render(request, 'webscanner.html')


def invalid_login():
    """
    Validate user login.
    :return:
    """
    return render('invalid_login.html')


def del_notify(request):
    """

    :return:
    """
    if request.method == 'GET':
        notify_id = request.GET['notify_id']

        notify_del = Notification.objects.filter(id=notify_id)
        notify_del.delete()

    return HttpResponseRedirect(reverse('dashboard:dashboard'))


def del_all_notify(request):
    """

    :return:
    """
    if request.method == 'GET':
        notify_del = Notification.objects.all()
        notify_del.delete()

    return HttpResponseRedirect(reverse('dashboard:dashboard'))


def index(request):
    """
    The function calling web scan Page.
    :param request:
    :return:
    """
    username = request.user.username
    all_urls = zap_spider_db.objects.filter(username=username)
    all_scans = zap_scans_db.objects.filter(username=username)
    all_spider_results = zap_spider_results.objects.filter(username=username)
    all_excluded_url = excluded_db.objects.filter(username=username)
    all_cookies = cookie_db.objects.filter(username=username)

    all_scans_db = project_db.objects.filter(username=username)

    all_notify = Notification.objects.unread()

    return render(request,
                  'webscanner.html',
                  {
                      'all_urls': all_urls,
                      'spider_status': spider_status,
                      'scans_status': scans_status,
                      'all_scans': all_scans,
                      'all_spider_results': all_spider_results,
                      'spider_alert': spider_alert,
                      'all_excluded_url': all_excluded_url,
                      'all_cookies': all_cookies,
                      'all_scans_db': all_scans_db,
                      'message': all_notify
                  }
                  )


@background(schedule=60)
def task(target_url, project_id, scanner):
    rescan_id = ''
    rescan = 'No'
    target__split = target_url.split(',')
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        # noinspection PyInterpreter
        if scanner == 'zap_scan':
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_schudle_zap_scan,
                args=(target, project_id, rescan_id, rescan, scan_id))
            thread.daemon = True
            thread.start()
        elif scanner == 'burp_scan':
            scan_id = uuid.uuid4()
            do_scan = burp_plugin.burp_scans(
                project_id,
                target,
                scan_id, user='admin')
            thread = threading.Thread(
                target=do_scan.scan_launch,
            )
            thread.daemon = True
            thread.start()

        return HttpResponse(status=200)


def web_task_launch(request):
    if request.method == 'GET':
        task_time = request.GET['time']

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
    username = request.user.username
    all_scans_db = project_db.objects.filter(username=username)
    all_scheduled_scans = task_schedule_db.objects.filter(username=username)

    if request.method == 'POST':
        scan_url = request.POST.get('url')
        scan_schedule_time = request.POST.get('datetime')
        project_id = request.POST.get('project_id')
        scanner = request.POST.get('scanner')
        # periodic_task = request.POST.get('periodic_task')
        periodic_task_value = request.POST.get('periodic_task_value')
        # periodic_task = 'Yes'
        if periodic_task_value == 'HOURLY':
            periodic_time = Task.HOURLY
        elif periodic_task_value == 'DAILY':
            periodic_time = Task.DAILY
        elif periodic_task_value == 'WEEKLY':
            periodic_time = Task.WEEKLY
        elif periodic_task_value == 'EVERY_2_WEEKS':
            periodic_time = Task.EVERY_2_WEEKS
        elif periodic_task_value == 'EVERY_4_WEEKS':
            periodic_time = Task.EVERY_4_WEEKS
        else:
            periodic_time = None
        dt_str = scan_schedule_time
        dt_obj = datetime.strptime(dt_str, '%d/%m/%Y %H:%M:%S %p')
        target__split = scan_url.split(',')
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
                    my_task = task(target, project_id, scanner, repeat=periodic_time, repeat_until=None)
                    task_id = my_task.id
                    print("Savedddddd taskid", task_id)
            save_scheadule = task_schedule_db(username=username, task_id=task_id, target=target,
                                              schedule_time=scan_schedule_time,
                                              project_id=project_id,
                                              scanner=scanner,
                                              periodic_task=periodic_task_value)
            save_scheadule.save()

    return render(request, 'web_scan_schedule.html',
                  {'all_scans_db': all_scans_db,
                   'all_scheduled_scans': all_scheduled_scans}
                  )


def del_web_scan_schedule(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    if request.method == "POST":
        task_id = request.POST.get('task_id')

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(',')
        split_length = target_split.__len__()
        print("split_length", split_length)
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = task_schedule_db.objects.filter(task_id=task_id, username=username)
            del_task.delete()
            del_task_schedule = Task.objects.filter(id=task_id, username=username)
            del_task_schedule.delete()

    return HttpResponseRedirect(reverse('webscanners:web_scan_schedule'))


def setting(request):
    """
    The function calling setting page.
    :param request:
    :return:
    """
    all_notify = Notification.objects.unread()

    jira_url = None
    j_username = None
    password = None
    # Loading settings

    username = request.user.username

    settings = load_settings.ArcherySettings(setting_file, username=username)

    lod_ov_user = settings.openvas_username()
    lod_ov_pass = settings.openvas_pass()
    lod_ov_host = settings.openvas_host()
    lod_ov_port = settings.openvas_port()
    lod_ov_enabled = settings.openvas_enabled()

    # Loading ZAP Settings
    zap_api_key = ''
    zap_hosts = ''
    zap_ports = ''
    zap_enable = False

    all_zap = zap_settings_db.objects.filter(username=username)
    for zap in all_zap:
        zap_api_key = zap.zap_api
        zap_hosts = zap.zap_url
        zap_ports = zap.zap_port
        zap_enable = zap.enabled

    lod_apikey = zap_api_key
    zap_host = zap_hosts
    zap_port = zap_ports

    # Loading Arachni Settings
    arachni_hosts = ''
    arachni_ports = ''

    all_arachni = arachni_settings_db.objects.filter(username=username)
    for arachni in all_arachni:
        arachni_hosts = arachni.arachni_url
        arachni_ports = arachni.arachni_port

    arachni_hosts = arachni_hosts
    arachni_ports = arachni_ports

    # Loading NMAP Vulners Settings
    nv_enabled = False
    nv_online = False
    nv_version = False
    nv_timing = 0

    all_nv = nmap_vulners_setting_db.objects.filter(username=username)
    for nv in all_nv:
        nv_enabled = bool(nv.enabled)
        nv_online = bool(nv.online)
        nv_version = bool(nv.version)
        nv_timing = int(nv.timing)

    # Loading Burp Settings

    burp_host = settings.burp_host()
    burp_port = settings.burp_port()
    burp_api_key = settings.burp_api_key()

    # Loading Email Settings

    all_email = email_db.objects.filter(username=username)

    # Load JIRA Setting
    jira_setting = jirasetting.objects.filter(username=username)

    for jira in jira_setting:
        jira_url = jira.jira_server
        j_username = jira.jira_username
        password = jira.jira_password
    jira_server = jira_url
    if j_username is None:
        jira_username = None
    else:
        jira_username = signing.loads(j_username)

    if password is None:
        jira_password = None
    else:
        jira_password = signing.loads(password)

    return render(request, 'setting.html',
                  {'apikey': lod_apikey,
                   'zapath': zap_host,
                   'zap_port': zap_port,
                   'zap_enable': zap_enable,
                   'arachni_hosts': arachni_hosts,
                   'arachni_ports': arachni_ports,
                   'lod_ov_user': lod_ov_user,
                   'lod_ov_pass': lod_ov_pass,
                   'lod_ov_host': lod_ov_host,
                   'lod_ov_enabled': lod_ov_enabled,
                   'lod_ov_port': lod_ov_port,
                   'burp_path': burp_host,
                   'burp_port': burp_port,
                   'burp_api_key': burp_api_key,
                   'all_email': all_email,
                   'jira_server': jira_server,
                   'jira_username': jira_username,
                   'jira_password': jira_password,
                   'nv_enabled': nv_enabled,
                   'nv_version': nv_version,
                   'nv_online': nv_online,
                   'nv_timing': nv_timing,
                   'message': all_notify,
                   })


def email_setting(request):
    """
    The function calling and updating Email Settings.
    :param request:
    :return:
    """
    username = request.user.username
    # Load Email Setting function
    all_email = email_db.objects.filter(username=username)

    if request.method == 'POST':
        subject = request.POST.get("email_subject")
        from_message = request.POST.get("email_message")
        email_to = request.POST.get("to_email")

        all_email.delete()

        save_email = email_db(
            username=username,
            subject=subject,
            message=from_message,
            recipient_list=email_to,
        )
        save_email.save()
        return HttpResponseRedirect(reverse('webscanners:setting'))

    return render(request, 'email_setting_form.html', {'all_email': all_email}
                  )


def burp_scan_launch(request):
    """
    Burp Scan Trigger.
    :param request:
    :return:
    """
    user = request.user
    username = request.user.username
    if request.POST.get("url"):
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        target__split = target_url.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print("Targets", target)
            scan_id = uuid.uuid4()
            date_time = datetime.now()
            scan_dump = burp_scan_db(username=username,
                                     scan_id=scan_id,
                                     project_id=project_id,
                                     url=target,
                                     date_time=date_time)
            scan_dump.save()
            try:
                do_scan = burp_plugin.burp_scans(
                    project_id,
                    target,
                    scan_id, user)
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

    return render(request, 'burpscanner/burp_scan_list.html')


def xml_upload(request):
    """
    Handling XML upload files.
    :param request:
    :return:
    """
    username = request.user.username
    all_project = project_db.objects.filter(username=username)

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES['xmlfile']
        scan_url = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "zap_scan":
            date_time = datetime.now()
            scan_dump = zap_scans_db(username=username,
                                     scan_url=scan_url,
                                     scan_scanid=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     vul_status=scan_status,
                                     rescan='No')
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            en_root_xml = ET.tostring(root_xml, encoding='utf8').decode('ascii', 'ignore')
            root_xml_en = ET.fromstring(en_root_xml)
            zap_xml_parser.xml_parser(username=username,
                                      project_id=project_id,
                                      scan_id=scan_id,
                                      root=root_xml_en)
            return HttpResponseRedirect(reverse('zapscanner:zap_scan_list'))
        elif scanner == "burp_scan":
            date_time = datetime.now()
            scan_dump = burp_scan_db(username=username,
                                     url=scan_url,
                                     scan_id=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     scan_status=scan_status)
            scan_dump.save()
            # Burp scan XML parser
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            en_root_xml = ET.tostring(root_xml, encoding='utf8').decode('ascii', 'ignore')
            root_xml_en = ET.fromstring(en_root_xml)

            burp_xml_parser.burp_scan_data(root_xml_en,
                                           project_id,
                                           scan_id,
                                           username=username)
            return HttpResponseRedirect(reverse('burpscanner:burp_scan_list'))

        elif scanner == "arachni":
            date_time = datetime.now()
            scan_dump = arachni_scan_db(username=username,
                                        url=scan_url,
                                        scan_id=scan_id,
                                        date_time=date_time,
                                        project_id=project_id,
                                        scan_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            arachni_xml_parser.xml_parser(username=username,
                                          project_id=project_id,
                                          scan_id=scan_id,
                                          root=root_xml,
                                          target_url=scan_url)
            print("Save scan Data")
            return HttpResponseRedirect(reverse('arachniscanner:arachni_scan_list'))

        elif scanner == 'netsparker':
            date_time = datetime.now()
            scan_dump = netsparker_scan_db(
                username=username,
                url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            netsparker_xml_parser.xml_parser(project_id=project_id,
                                             scan_id=scan_id,
                                             root=root_xml, username=username)

            return HttpResponseRedirect(reverse('netsparkerscanner:netsparker_scan_list'))
        elif scanner == 'webinspect':
            date_time = datetime.now()
            scan_dump = webinspect_scan_db(
                username=username,
                url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            webinspect_xml_parser.xml_parser(project_id=project_id,
                                             scan_id=scan_id,
                                             root=root_xml,
                                             username=username)

            return HttpResponseRedirect(reverse('webinspectscanner:webinspect_scan_list'))

        elif scanner == 'acunetix':
            date_time = datetime.now()
            scan_dump = acunetix_scan_db(
                username=username,
                url=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status
            )
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            acunetix_xml_parser.xml_parser(username=username,
                                           project_id=project_id,
                                           scan_id=scan_id,
                                           root=root_xml)

            return HttpResponseRedirect(reverse('acunetixscanner:acunetix_scan_list'))

        elif scanner == 'dependencycheck':
            date_time = datetime.now()
            scan_dump = dependencycheck_scan_db(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
                username=username
            )
            scan_dump.save()
            data = etree.parse(xml_file)
            root = data.getroot()
            dependencycheck_report_parser.xml_parser(project_id=project_id,
                                                     scan_id=scan_id,
                                                     data=root,
                                                     username=username
                                                     )

            return HttpResponseRedirect(reverse('dependencycheck:dependencycheck_list'))

        elif scanner == 'checkmarx':
            date_time = datetime.now()
            scan_dump = checkmarx_scan_db(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
                username=username
            )
            scan_dump.save()
            data = etree.parse(xml_file)
            root = data.getroot()
            checkmarx_xml_report_parser.checkmarx_report_xml(project_id=project_id,
                                                             scan_id=scan_id,
                                                             data=root,
                                                             username=username
                                                             )

            return HttpResponseRedirect(reverse('checkmarx:checkmarx_list'))

        elif scanner == 'findbugs':
            date_time = datetime.now()
            scan_dump = findbugs_scan_db(
                project_name=scan_url,
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
                username=username
            )
            scan_dump.save()
            tree = ET.parse(xml_file)
            root = tree.getroot()
            findbugs_report_parser.xml_parser(project_id=project_id,
                                              scan_id=scan_id,
                                              root=root,
                                              username=username)

            return HttpResponseRedirect(reverse('findbugs:findbugs_list'))

        elif scanner == 'nikto':
            date_time = datetime.now()
            scan_dump = nikto_result_db(
                date_time=date_time,
                scan_url=scan_url,
                scan_id=scan_id,
                project_id=project_id,
            )
            scan_dump.save()

            nikto_html_parser(xml_file, project_id, scan_id)

            return HttpResponseRedirect(reverse('tools:nikto'))

    return render(request, 'upload_xml.html', {'all_project': all_project})


def add_cookies(request):
    """
    Cookies storing into Archery Database.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        target_url = request.POST.get('url')
        target_cookies = request.POST.get('cookies')
        all_cookie_url = cookie_db.objects.filter(Q(url__icontains=target_url, username=username))
        for da in all_cookie_url:
            global cookies
            cookies = da.url

        if cookies == target_url:
            cookie_db.objects.filter(Q(url__icontains=target_url, username=username)).update(cookie=target_cookies)
            return HttpResponseRedirect(reverse('webscanners:index'))
        else:
            data_dump = cookie_db(url=target_url,
                                  cookie=target_cookies,
                                  username=username
                                  )
            data_dump.save()
            return HttpResponseRedirect(reverse('webscanners:index'))

    return render(request, 'cookie_add.html')


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
        driver.get(url, )
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
    f = open('cookies.txt', 'w+')
    for cookie in all_cookies:
        cookie_value = cookie['name'] + '=' + cookie['value'] + ';'
        f.write(cookie_value)
    f.close()
    driver.close()

    return HttpResponseRedirect(reverse('webscanners:index'))


def cookies_list(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_cookies = cookie_db.objects.filter(username=username)

    return render(request, 'cookies_list.html', {'all_cookies': all_cookies})


def del_cookies(request):
    username = request.user.username
    if request.method == 'POST':
        cookie_url = request.POST.get('url')
        cookies_item = str(cookie_url)
        cooki_split = cookies_item.replace(" ", "")
        target_split = cooki_split.split(',')
        split_length = target_split.__len__()
        print("split_length", split_length)
        for i in range(0, split_length):
            cookies_target = target_split.__getitem__(i)
            print(cookies_target)
            del_cookie = cookie_db.objects.filter(url=cookies_target, username=username)
            del_cookie.delete()
            zap_plugin.zap_replacer(target_url=cookies_target)
        return HttpResponseRedirect(reverse('webscanners:cookies_list'))

    return render(request, 'cookies_list.html')


def sel_login(request):
    """
    Lgoin perfrom using Selenium.
    :param request:
    :return:
    """
    username = request.user.username
    action_vul = request.POST.get("action", )
    url_da = request.POST.get("url_login", )
    if action_vul == "open_page":
        global driver
        driver = webdriver.Firefox()
        slem(driver, url_da)
    elif action_vul == "save_cookie":
        save_cookie(driver)
        read_f = open('cookies.txt', 'r')

        for cookie_data in read_f:

            print(cookie_data)
            all_cookie_url = cookie_db.objects.filter(Q(url__icontains=new_uri, username=username))
            for da in all_cookie_url:
                global cookies
                cookies = da.url

            if cookies == new_uri:
                cookie_db.objects.filter(Q(url__icontains=new_uri, username=username)).update(cookie=cookie_data)
                return HttpResponseRedirect(reverse('webscanners:index'))
            else:
                data_dump = cookie_db(url=new_uri,
                                      cookie=cookie_data,
                                      username=username,
                                      )
                data_dump.save()
                return HttpResponseRedirect(reverse('webscanners:index'))
        # messages.add_message(request, messages.SUCCESS, 'Cookies stored')

        return HttpResponseRedirect(reverse('webscanners:index'))
    return render(request, 'webscanner.html')


def exclude_url(request):
    """
    Excluding URL from scanner. Save excluded URL in Archery Database.
    :param request:
    :return:
    """
    username = request.user.username
    exclud = request.POST.get("exclude_url", )
    exclude_save = excluded_db(exclude_url=exclud,
                               username=username
                               )
    exclude_save.save()

    return render(request, 'webscanner.html', )


def exluded_url_list(request):
    """

    :param request:
    :return:
    """
    username = request.user.username
    all_excluded_url = excluded_db.objects.filter(username=username)

    if request.method == 'POST':
        exclude_url = request.POST.get('exclude_url')
        exluded_item = str(exclude_url)
        exclude_split = exluded_item.replace(" ", "")
        target_split = exclude_split.split(',')
        split_length = target_split.__len__()
        for i in range(0, split_length):
            exclude_target = target_split.__getitem__(i)

            del_excluded = excluded_db.objects.filter(username=username, exclude_url=exclude_target)
            del_excluded.delete()

            return HttpResponseRedirect(reverse('zapscanner:excluded_url_list'))

    return render(request, 'excludedurl_list.html', {'all_excluded_url': all_excluded_url})
