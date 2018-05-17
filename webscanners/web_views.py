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

from __future__ import unicode_literals

import os
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from itertools import chain
from django.contrib import auth
from django.contrib import messages
from django.contrib.auth.models import User
from django.core import signing
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import render, render_to_response, HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_protect
from easy_pdf.views import render_to_pdf_response
from selenium import webdriver
from stronghold.decorators import public
from archerysettings import load_settings, save_settings
from networkscanners.models import scan_save_db
from projects.models import project_db
from scanners.scanner_parser.web_scanner import zap_xml_parser, arachni_xml_parser
from scanners.scanner_plugin.web_scanner import burp_plugin
from scanners.scanner_plugin.web_scanner import zap_plugin
from webscanners.models import zap_scan_results_db, \
    zap_scans_db, \
    zap_spider_db, \
    zap_spider_results, \
    cookie_db, excluded_db, \
    burp_scan_db, burp_scan_result_db, \
    arachni_scan_db, arachni_scan_result_db, task_schedule_db
from background_task import background
from datetime import datetime
from background_task.models import Task
import os
from jiraticketing.models import jirasetting
import subprocess


# from background_task.management.commands.process_tasks import Command
#
# Command()

# log_path = os.getcwd() + '/' + 'task_background.log'
# with open(log_path, 'w+') as log_file:
# subprocess.Popen("python manage.py process_tasks", shell=False)

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
target_url = None
scan_ip = None
burp_status = 0
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
vuln_id = ""
methods = ""
dec_res = ""
dec_req = ""
decd_req = ""
scanner = ""
all_scan_url = ""
all_url_vuln = ""


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
        return HttpResponseRedirect('/')
    else:
        return HttpResponseRedirect('/')


@public
def logout(request):
    """
    Logout request
    :param request:
    :return:
    """
    auth.logout(request)
    return render_to_response("logout.html")


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
        user = User.objects.create_user(username, email, password)
        user.save()
        return HttpResponseRedirect('/login/')

    return render(request,
                  'signup.html')


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
    return render_to_response('invalid_login.html')


def index(request):
    """
    The function calling web scan Page.
    :param request:
    :return:
    """
    all_urls = zap_spider_db.objects.all()
    all_scans = zap_scans_db.objects.all()
    all_spider_results = zap_spider_results.objects.all()
    all_excluded_url = excluded_db.objects.all()
    all_cookies = cookie_db.objects.all()

    all_scans_db = project_db.objects.all()

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
                      'all_scans_db': all_scans_db
                  }
                  )


def launch_web_scan(target_url, project_id, rescan_id, rescan):
    """
    The function Launch ZAP Scan.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(target_url, project_id, rescan_id, rescan)
    zap.exclude_url()
    zap.cookies()
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    print "Spider Completed"
    time.sleep(5)
    print 'Scanning Target %s' % target_url
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    un_scanid = uuid.uuid4()
    date_time = datetime.now()
    try:
        save_all_scan = zap_scans_db(
            project_id=project_id,
            scan_url=target_url,
            scan_scanid=un_scanid,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
        )

        save_all_scan.save()
    except Exception as e:
        print e
    zap.zap_scan_status(
        scan_id=zap_scan_id,
        un_scanid=un_scanid
    )
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result()
    time.sleep(5)
    save_all_vuln = zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=un_scanid,
    )
    print save_all_vuln
    # return HttpResponse(status=201)


def web_scan(request):
    """
    The function trigger ZAP scan.
    :param request:
    :return:
    """
    global scans_status
    if request.POST.get("url", ):
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        print "Project id", project_id
        rescan_id = None
        rescan = 'No'
        print target_url
        target_item = str(target_url)
        value = target_item.replace(" ", "")
        target__split = value.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print "targetssss -", target
            thread = threading.Thread(
                target=launch_web_scan,
                args=(target, project_id, rescan_id, rescan))
            thread.daemon = True
            thread.start()

        # launch_web_scan(target_url, project_id)
        if scans_status == '100':
            scans_status = "0"
        else:
            return scans_status
        return HttpResponse(status=200)

    return render(request,
                  'scan_list.html')


@background(schedule=60)
def task(target_url, project_id, scanner):
    rescan_id = ''
    rescan = 'No'
    target__split = target_url.split(',')
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        if scanner == 'zap_scan':
            thread = threading.Thread(
                target=launch_web_scan,
                args=(target, project_id, rescan_id, rescan))
            thread.daemon = True
            thread.start()
        elif scanner == 'burp_scan':
            scan_id = uuid.uuid4()
            do_scan = burp_plugin.burp_scans(
                project_id,
                target,
                scan_id)
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
        print task_time

        for ta in t:
            print ta.run_at
            print ta.id

    return HttpResponse(status=200)


def web_scan_schedule(request):
    """

    :param request:
    :return:
    """
    all_scans_db = project_db.objects.all()
    all_scheduled_scans = task_schedule_db.objects.all()

    if request.method == 'POST':
        scan_url = request.POST.get('url')
        scan_schedule_time = request.POST.get('datetime')
        project_id = request.POST.get('project_id')
        scanner = request.POST.get('scanner')
        # periodic_task = request.POST.get('periodic_task')
        periodic_task_value = request.POST.get('periodic_task_value')
        # periodic_task = 'Yes'
        print 'scanner-', scanner

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

        print "scan_url", scan_url
        print "schedule", scan_schedule_time

        # task(scan_url, project_id, schedule=dt_obj)

        target__split = scan_url.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)

            if scanner == 'zap_scan':
                if periodic_task_value == 'None':
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                    print "Savedddddd taskid", task_id
                else:

                    my_task = task(target, project_id, scanner, repeat=periodic_time, repeat_until=None)
                    task_id = my_task.id
                    print "Savedddddd taskid", task_id
            elif scanner == 'burp_scan':
                if periodic_task_value == 'None':
                    my_task = task(target, project_id, scanner, schedule=dt_obj)
                    task_id = my_task.id
                else:
                    my_task = task(target, project_id, scanner, repeat=periodic_time, repeat_until=None)
                    task_id = my_task.id
                    print "Savedddddd taskid", task_id
            save_scheadule = task_schedule_db(task_id=task_id, target=target,
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

    if request.method == "POST":
        task_id = request.POST.get('task_id')

        scan_item = str(task_id)
        taskid = scan_item.replace(" ", "")
        target_split = taskid.split(',')
        split_length = target_split.__len__()
        print "split_lenght", split_length
        for i in range(0, split_length):
            task_id = target_split.__getitem__(i)
            del_task = task_schedule_db.objects.filter(task_id=task_id)
            del_task.delete()
            del_task_schedule = Task.objects.filter(id=task_id)
            del_task_schedule.delete()

    return HttpResponseRedirect('/webscanners/web_scan_schedule')


def zap_rescan(request):
    """

    :param request:
    :return:
    """
    if request.method == 'POST':
        scan_url = request.POST.get('scan_url')
        project_id = request.POST.get('project_id')
        rescan_id = request.POST.get('old_scan_id')
        rescan = 'Yes'

        thread = threading.Thread(
            target=launch_web_scan,
            args=(scan_url, project_id, rescan_id, rescan))
        thread.daemon = True
        thread.start()
        messages.add_message(request, messages.SUCCESS, 'Re-Scan Launched')

    return HttpResponseRedirect('/webscanners/scans_list/')


def scan_list(request):
    """
    The function listing all ZAP Web scans.
    :param request:
    :return:
    """
    all_scans = zap_scans_db.objects.filter(rescan='No')
    rescan_all_scans = zap_scans_db.objects.filter(rescan='Yes')

    return render(request,
                  'scan_list.html',
                  {'all_scans': all_scans,
                   'rescan_all_scans': rescan_all_scans})


def list_web_vuln(request):
    """
    The function returning all Web Application Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    zap_all_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_id).values(
        'name',
        'risk',
        'vuln_color',
        'scan_id').distinct()

    return render(request,
                  'list_web_vuln.html',
                  {'zap_all_vul': zap_all_vul, 'scan_id': scan_id})


def vuln_details(request):
    """
    The function retiring Web Application vulnerabilities details.
    :param request:
    :return:
    """
    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_vul = request.GET['scan_id']
        scan_name = request.GET['scan_name']
    if request.method == "POST":
        false_positive = request.POST.get('false')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        zap_scan_results_db.objects.filter(
            vuln_id=vuln_id,
            scan_id=scan_id).update(false_positive=false_positive)
        return HttpResponseRedirect(
            '/webscanners/zap_vul_details/?scan_id=%s&scan_name=%s' % (
                scan_id,
                vuln_name
            )
        )
    zap_all_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_vul,
        false_positive='No',
        name=scan_name
    ).order_by('name')
    zap_all_false_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_vul,
        name=scan_name,
        false_positive='Yes').order_by('name')

    return render(request,
                  'vuln_details.html',
                  {'zap_all_vul': zap_all_vul,
                   'scan_vul': scan_vul,
                   'zap_all_false_vul': zap_all_false_vul,
                   'jira_url': jira_url
                   })


def setting(request):
    """
    The function calling setting page.
    :param request:
    :return:
    """
    # Loading settings
    settings = load_settings.ArcherySettings(setting_file)

    # Loading OpenVAS Settings
    ov_user = settings.openvas_username()
    ov_pass = settings.openvas_pass()
    ov_ip = settings.openvas_host()
    lod_ov_user = signing.loads(ov_user)
    lod_ov_pass = signing.loads(ov_pass)
    lod_ov_ip = signing.loads(ov_ip)

    # Loading ZAP Settings
    lod_apikey = settings.zap_api_key()
    zap_host = settings.zap_host()
    zap_port = settings.zap_port()

    # Loading Burp Settings
    burp_host = settings.burp_host()
    burp_port = settings.burp_port()

    # Loading Email Settings
    email_subject = settings.email_subject()
    email_from = settings.email_from()
    to_email = settings.email_to()

    # Load JIRA Setting
    jira_setting = jirasetting.objects.all()

    for jira in jira_setting:
        jira_url = jira.jira_server
        username = jira.jira_username
        password = jira.jira_password
    jira_server = jira_url
    jira_username = signing.loads(username)
    jira_password = signing.loads(password)

    return render(request, 'setting.html',
                  {'apikey': lod_apikey,
                   'zapath': zap_host,
                   'zap_port': zap_port,
                   'lod_ov_user': lod_ov_user,
                   'lod_ov_pass': lod_ov_pass,
                   'lod_ov_ip': lod_ov_ip,
                   'burp_path': burp_host,
                   'burp_port': burp_port,
                   'email_subject': email_subject,
                   'email_from': email_from,
                   'to_email': to_email,
                   'jira_server': jira_server,
                   'jira_username': jira_username,
                   'jira_password': jira_password,
                   })


def zap_setting(request):
    """
    The function calling ZAP Scanner setting page.
    :param request:
    :return:
    """
    return render(request,
                  'settingform.html')


def zap_set_update(request):
    """
    The function Update the ZAP settings.
    :param request:
    :return:
    """
    # Load ZAP setting function
    save_setting = save_settings.SaveSettings(setting_file)

    if request.method == 'POST':
        apikey = request.POST.get("apikey", )
        zaphost = request.POST.get("zappath", )
        port = request.POST.get("port", )

        save_setting.save_zap_settings(apikey=apikey,
                                       zaphost=zaphost,
                                       zaport=port)

    messages.add_message(request,
                         messages.SUCCESS,
                         'ZAP Setting Updated ')

    return render(request,
                  'settingform.html')


def email_setting(request):
    """
    The function calling and updating Email Settings.
    :param request:
    :return:
    """
    # Load Email Setting function
    save_email_setting = save_settings.SaveSettings(setting_file)

    if request.method == 'POST':
        subject = request.POST.get("email_subject")
        from_email = request.POST.get("from_email")
        email_to = request.POST.get("to_email")

        save_email_setting.save_email_settings(
            email_subject=subject,
            email_from=from_email,
            email_to=email_to
        )
    return render(request, 'email_setting_form.html')


def scan_table(request):
    """
    Scan Table.
    :param request:
    :return:
    """
    all_scans = zap_scans_db.objects.all()

    return render(request, 'scan_table.html', {'all_scans': all_scans})


def del_scan(request):
    """
    The function deleting scans from ZAP scans.
    :param request:
    :return:
    """
    try:
        if request.method == 'POST':
            item_id = request.POST.get("scan_scanid")
            scan_url = request.POST.get("scan_url")
            scan_item = str(item_id)
            ip = scan_item.replace(" ", "")
            target_split = ip.split(',')
            split_length = target_split.__len__()
            print "split_lenght", split_length
            for i in range(0, split_length):
                target = target_split.__getitem__(i)

                item = zap_scans_db.objects.filter(scan_scanid=target,
                                                   )
                item.delete()
                item_results = zap_scan_results_db.objects.filter(scan_id=target,
                                                                  )
                item_results.delete()
                messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
            return HttpResponseRedirect('/webscanners/scans_list/')
    except Exception as e:
        print "Error Got !!!"


def dashboard(request):
    """
    Cool Dashboard working function.
    :param request:
    :return:
    """
    global project_id, \
        target_url, \
        scan_ip, \
        scanner, \
        all_scan_url, \
        all_url_vuln
    all_data = project_db.objects.all()
    try:
        if request.method == 'POST':
            if request.POST.get("project_id"):
                project_id = request.POST.get("project_id")
            elif request.POST.get("target_url"):
                target_url = request.POST.get("target_url")
            elif request.POST.get("scan_ip"):
                scan_ip = request.POST.get("scan_ip")
            zap_scan_url = zap_scans_db.objects.filter(project_id=project_id)
            zap_url_vuln = zap_scans_db.objects.filter(project_id=project_id,
                                                       scan_url=target_url)
            burp_scan_url = burp_scan_db.objects.filter(project_id=project_id)
            burp_url_vuln = burp_scan_db.objects.filter(project_id=project_id,
                                                        url=target_url)

            all_scan_url = chain(zap_scan_url, burp_scan_url)
            all_url_vuln = chain(zap_url_vuln, burp_url_vuln)
    except Exception as e:
        print "Error Got !!!!"
    all_ip = scan_save_db.objects.filter(project_id=project_id)
    all_ip_vul = scan_save_db.objects.filter(project_id=project_id,
                                             scan_ip=scan_ip)

    return render(request,
                  'web_dashboard.html',
                  {'all_data': all_data,
                   'all_scan_url': all_scan_url,
                   'all_url_vuln': all_url_vuln,
                   'all_ip': all_ip,
                   'all_ip_vul': all_ip_vul})


def dashboard_network(request):
    """
    Network Dashboard calling page.
    :param request:
    :return:
    """
    global project_id, target_url, scan_ip
    all_data = project_db.objects.all()
    if request.method == 'POST':
        if request.POST.get("project_id"):
            project_id = request.POST.get("project_id")
        elif request.POST.get("scan_ip"):
            scan_ip = request.POST.get("scan_ip")
    all_ip = scan_save_db.objects.filter(project_id=project_id)
    all_ip_vul = scan_save_db.objects.filter(project_id=project_id, scan_ip=scan_ip)

    return render(request, 'network_dashboard.html',
                  {'all_data': all_data, 'all_ip': all_ip,
                   'all_ip_vul': all_ip_vul})


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
        print "Error Got !!!"


def save_cookie(driver):
    """
    Cookie grabber.
    :param driver:
    :return:
    """
    all_cookies = driver.get_cookies()
    print all_cookies
    f = open('cookies.txt', 'w+')
    for cookie in all_cookies:
        cookie_value = cookie['name'] + '=' + cookie['value'] + ';'
        print cookie_value
        f.write(cookie_value)
    f.close()
    driver.close()

    return HttpResponseRedirect('/webscanners/')


def sel_login(request):
    """
    Lgoin perfrom using Selenium.
    :param request:
    :return:
    """
    action_vul = request.POST.get("action", )
    url_da = request.POST.get("url_login", )
    print action_vul
    print url_da
    if action_vul == "open_page":
        global driver
        driver = webdriver.Firefox()
        slem(driver, url_da)
    elif action_vul == "save_cookie":
        save_cookie(driver)
        read_f = open('cookies.txt', 'r')
        del_all_cookie = cookie_db.objects.all()
        del_all_cookie.delete()
        print "url from cookie : ", new_uri
        for cookie_data in read_f:
            print "Cookies from text :", cookie_data
            cookie_save = cookie_db(url=new_uri, cookie=cookie_data)
            cookie_save.save()
        messages.add_message(request, messages.SUCCESS, 'Cookies stored')

    return HttpResponseRedirect('/webscanners/')


def exclude_url(request):
    """
    Excluding URL from scanner. Save excluded URL in Archery Database.
    :param request:
    :return:
    """
    exclud = request.POST.get("exclude_url", )
    exclude_save = excluded_db(exclude_url=exclud)
    exclude_save.save()

    return render(request, 'webscanner.html', )


def edit_vuln(request):
    """
    Edit vulnerability.
    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("vuln_id", )
        name = request.POST.get("name", )
        risk = request.POST.get("risk", )
        url = request.POST.get("url", )
        description = request.POST.get("description", )
        solution = request.POST.get("solution", )
        param = request.POST.get("param", )
        sourceid = request.POST.get("sourceid", )
        attack = request.POST.get("attack", )
        reference = request.POST.get("reference", )
        global vul_col
        if risk == 'High':
            vul_col = "important"
        elif risk == 'Medium':
            vul_col = "warning"
        elif risk == 'Low':
            vul_col = "info"
        else:
            vul_col = "info"
        zap_scan_results_db.objects.filter(vuln_id=vuln_id).update(name=name,
                                                                   vuln_color=vul_col,
                                                                   risk=risk,
                                                                   url=url,
                                                                   description=description,
                                                                   solution=solution,
                                                                   param=param,
                                                                   sourceid=sourceid,
                                                                   attack=attack,
                                                                   reference=reference)

        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')
        return HttpResponseRedirect("/webscanners/vuln_dat/?vuln_id=%s" % vuln_id)
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    edit_vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'edit_vuln_data.html', {'edit_vul_dat': edit_vul_dat})


def del_vuln(request):
    """
    Delete Vulnerability from database.
    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_lenght", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = zap_scan_results_db.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        zap_all_vul = zap_scan_results_db.objects.filter(scan_id=un_scanid).values('name', 'risk',
                                                                                   'vuln_color').distinct()
        total_vul = len(zap_all_vul)
        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))

        zap_scans_db.objects.filter(scan_scanid=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                                  medium_vul=total_medium, low_vul=total_low)
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/webscanners/web_vuln_list/?scan_id=%s" % un_scanid)


def vuln_check(request):
    """
    Calling vulnerability Data list.
    :param request:
    :return:
    """
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'vuln_data.html', {'vul_dat': vul_dat})


def edit_vuln_check(request):
    """
    Editing vulnerability data.
    :param request:
    :return:
    """
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    edit_vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'edit_vuln_data.html', {'edit_vul_dat': edit_vul_dat})


def add_vuln(request):
    """
    Adding vulnerability in Databse.
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scanners = request.GET['scanner']
    else:
        scan_id = ''
        scanners = ''
    if request.method == 'POST':
        vuln_id = uuid.uuid4()
        scan_id = request.POST.get("scan_id")
        scanners = request.POST.get("scanners")
        vuln_name = request.POST.get("vuln_name")
        risk = request.POST.get("risk")
        url = request.POST.get("url")
        param = request.POST.get("param")
        sourceid = request.POST.get("sourceid")
        attack = request.POST.get("attack")
        ref = request.POST.get("ref")
        description = request.POST.get("description")
        solution = request.POST.get("solution")
        req_header = request.POST.get("req_header")
        res_header = request.POST.get("res_header")
        vuln_col = request.POST.get("vuln_color")

        if scanners == 'zap':
            save_vuln = zap_scan_results_db(scan_id=scan_id,
                                            vuln_color=vuln_col,
                                            risk=risk, url=url,
                                            param=param,
                                            sourceid=sourceid,
                                            attack=attack,
                                            vuln_id=vuln_id,
                                            name=vuln_name,
                                            description=description,
                                            reference=ref,
                                            solution=solution,
                                            requestHeader=req_header,
                                            responseHeader=res_header)
            save_vuln.save()
            messages.success(request, "Vulnerability Added")
            zap_all_vul = zap_scan_results_db.objects.filter(
                scan_id=scan_id).values('name',
                                        'risk',
                                        'vuln_color').distinct()
            total_vul = len(zap_all_vul)
            total_high = len(zap_all_vul.filter(risk="High"))
            total_medium = len(zap_all_vul.filter(risk="Medium"))
            total_low = len(zap_all_vul.filter(risk="Low"))

            zap_scans_db.objects.filter(
                scan_scanid=scan_id).update(total_vul=total_vul,
                                            high_vul=total_high,
                                            medium_vul=total_medium,
                                            low_vul=total_low)
            return HttpResponseRedirect("/webscanners/web_vuln_list/?scan_id=%s" % scan_id)

        elif scanners == 'burp':
            save_burp_vuln = burp_scan_result_db(scan_id=scan_id,
                                                 severity_color=vuln_col,
                                                 severity=risk,
                                                 host=url,
                                                 location=param,
                                                 vuln_id=vuln_id,
                                                 name=vuln_name,
                                                 issueBackground=description,
                                                 references=ref,
                                                 remediationBackground=solution,
                                                 scan_request=req_header,
                                                 scan_response=res_header)
            save_burp_vuln.save()

            burp_all_vul = burp_scan_result_db.objects.filter(scan_id=scan_id)

            total_vul = len(burp_all_vul)
            total_high = len(burp_all_vul.filter(severity="High"))
            total_medium = len(burp_all_vul.filter(severity="Medium"))
            total_low = len(burp_all_vul.filter(severity="Low"))

            burp_scan_db.objects.filter(
                scan_id=scan_id).update(total_vul=total_vul,
                                        high_vul=total_high,
                                        medium_vul=total_medium,
                                        low_vul=total_low)

            return HttpResponseRedirect("/webscanners/burp_vuln_list?scan_id=%s" % scan_id)

    return render(request, 'add_vuln.html', {'scan_id': scan_id, 'scanners': scanners})


def create_vuln(request):
    """
    Add vulnerabilities.
    :param request:
    :return:
    """
    return render(request, 'add_vuln.html')


def scan_pdf_gen(request):
    """
    Generate Report in PDF format.
    :param request:
    :return:
    """
    all_scan = zap_scans_db.objects.all()

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")
        vuln_scan = zap_scan_results_db.objects.filter(scan_id=scan_id)
        zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_id).values('name',
                                                                                 'risk',
                                                                                 'vuln_color',
                                                                                 'scan_id').distinct()

        return render_to_pdf_response(request,
                                      template=str('pdf_generate.html'),
                                      download_filename=None,
                                      content_type='application/pdf',
                                      context={'all_scan': all_scan,
                                               'vuln_scan': vuln_scan,
                                               'scan_url': scan_url,
                                               'zap_all_vul': zap_all_vul})


def burp_setting(request):
    """
    Load Burp Settings.
    :param request:
    :return:
    """
    save_burp_setting = save_settings.SaveSettings(setting_file)

    if request.method == 'POST':
        burphost = request.POST.get("burpath")
        burport = request.POST.get("burport")

        save_burp_setting.save_burp_settings(burphost=burphost,
                                             burport=burport)

    return render(request, 'burp_setting_form.html')


def burp_scan_launch(request):
    """
    Burp Scan Trigger.
    :param request:
    :return:
    """
    global vuln_id, burp_status
    if request.POST.get("url"):
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        target__split = target_url.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            print "Targets", target
            scan_id = uuid.uuid4()
            date_time = datetime.now()
            scan_dump = burp_scan_db(scan_id=scan_id,
                                     project_id=project_id,
                                     url=target,
                                     date_time=date_time)
            scan_dump.save()
            try:
                do_scan = burp_plugin.burp_scans(
                    project_id,
                    target,
                    scan_id)
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
                print e

    return render(request, 'scan_list.html')


def burp_scan_list(request):
    """
    List all burp scans.
    :param request:
    :return:
    """
    all_burp_scan = burp_scan_db.objects.all()

    return render(request,
                  'burp_scan_list.html',
                  {'all_burp_scan': all_burp_scan})


def burp_list_vuln(request):
    """
    List all Burp Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None
    burp_all_vul = burp_scan_result_db.objects.filter(scan_id=scan_id).values('name',
                                                                              'severity',
                                                                              'severity_color',
                                                                              'scan_id').distinct()
    return render(request,
                  'burp_list_vuln.html',
                  {'burp_all_vul': burp_all_vul,
                   'scan_id': scan_id})


def burp_vuln_data(request):
    """
    Add Burp Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']
    else:
        vuln_id = None
    vuln_data = burp_scan_result_db.objects.filter(vuln_id=vuln_id)

    return render(request,
                  'burp_vuln_data.html',
                  {'vuln_data': vuln_data})


def burp_vuln_out(request):
    """
    The function calling burp vulnerability details.
    :param request:
    :return:
    """
    jira = jirasetting.objects.all()
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        name = request.GET['scan_name']
    if request.method == "POST":
        false_positive = request.POST.get('false')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        burp_scan_result_db.objects.filter(vuln_id=vuln_id,
                                           scan_id=scan_id).update(false_positive=false_positive)
        return HttpResponseRedirect(
            '/webscanners/burp_vuln_out/?scan_id=%s&scan_name=%s' % (scan_id,
                                                                     vuln_name))
    vuln_data = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                   name=name,
                                                   false_positive='No')
    false_data = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                    name=name,
                                                    false_positive='Yes')

    return render(request, 'burp_vuln_out.html', {'vuln_data': vuln_data,
                                                  'false_data': false_data,
                                                  'jira_url': jira_url
                                                  })


def del_burp_scan(request):
    """
    Delete Burp scans.
    :param request:
    :return:
    """
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_lenght", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            item = burp_scan_db.objects.filter(scan_id=scan_id)
            item.delete()
            item_results = burp_scan_result_db.objects.filter(scan_id=scan_id)
            item_results.delete()
            messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/webscanners/burp_scan_list/')


def del_burp_vuln(request):
    """
    Delete Vulnerability from database.
    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_lenght", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = burp_scan_result_db.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        burp_all_vul = burp_scan_result_db.objects.filter(scan_id=un_scanid).values('name', 'severity',
                                                                                    'severity_color').distinct()
        total_vul = len(burp_all_vul)
        total_high = len(burp_all_vul.filter(severity="High"))
        total_medium = len(burp_all_vul.filter(severity="Medium"))
        total_low = len(burp_all_vul.filter(severity="Low"))

        burp_scan_db.objects.filter(scan_id=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                              medium_vul=total_medium, low_vul=total_low)
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/webscanners/burp_vuln_list?scan_id=%s" % un_scanid)


def edit_burp_vuln(request):
    """
    Edit Burp vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    edit_vul_dat = burp_scan_result_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    if request.method == 'POST':
        vuln_id = request.POST.get("vuln_id", )
        scan_id = request.POST.get("scan_id", )
        name = request.POST.get("name", )
        severity = request.POST.get("severity", )
        host = request.POST.get("host", )
        path = request.POST.get("path", )
        issuedetail = request.POST.get("issuedetail")
        description = request.POST.get("description", )
        solution = request.POST.get("solution", )
        location = request.POST.get("location", )
        vulnClass = request.POST.get("reference", )

        global vul_col

        if severity == 'High':
            vul_col = "important"
        elif severity == 'Medium':
            vul_col = "warning"
        elif severity == 'Low':
            vul_col = "info"
        else:
            vul_col = "info"

        print "edit_vul :", name

        burp_scan_result_db.objects.filter(
            vuln_id=vuln_id).update(name=name,
                                    severity_color=vul_col,
                                    severity=severity,
                                    host=host, path=path,
                                    location=location,
                                    issueDetail=issuedetail,
                                    issueBackground=description,
                                    remediationBackground=solution,
                                    vulnerabilityClassifications=vulnClass)
        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/webscanners/burp_vuln_data/?vuln_id=%s" % vuln_id)

    return render(request, 'edit_burp_vuln.html', {'edit_vul_dat': edit_vul_dat})


def xml_upload(request):
    """
    Handling XML upload files.
    :param request:
    :return:
    """
    all_project = project_db.objects.all()

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES['xmlfile']
        scan_url = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "zap_scan":
            date_time = datetime.now()
            scan_dump = zap_scans_db(scan_url=scan_url,
                                     scan_scanid=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     vul_status=scan_status,
                                     rescan='No')
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            zap_xml_parser.xml_parser(project_id=project_id,
                                      scan_id=scan_id,
                                      root=root_xml)
            return HttpResponseRedirect("/webscanners/scans_list/")
        elif scanner == "burp_scan":
            date_time = datetime.now()
            scan_dump = burp_scan_db(url=scan_url,
                                     scan_id=scan_id,
                                     date_time=date_time,
                                     project_id=project_id,
                                     scan_status=scan_status)
            scan_dump.save()
            # Burp scan XML parser
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            do_xml_data = burp_plugin.burp_scans(project_id,
                                                 target_url,
                                                 scan_id)
            do_xml_data.burp_scan_data(root_xml)
            print "Save scan Data"
            return HttpResponseRedirect("/webscanners/burp_scan_list")

        elif scanner == "arachni":
            print scanner
            print xml_file
            print scan_url
            date_time = datetime.now()
            scan_dump = arachni_scan_db(url=scan_url,
                                        scan_id=scan_id,
                                        date_time=date_time,
                                        project_id=project_id,
                                        scan_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            arachni_xml_parser.xml_parser(project_id=project_id,
                                          scan_id=scan_id,
                                          root=root_xml)
            print "Save scan Data"
            return HttpResponseRedirect("/webscanners/arachni_scan_list")

    return render(request, 'upload_xml.html', {'all_project': all_project})


def add_cookies(request):
    """
    Cookies storing into Archery Database.
    :param request:
    :return:
    """
    if request.method == 'POST':
        target_url = request.POST.get('url')
        target_cookies = request.POST.get('cookies')
        all_cookie_url = cookie_db.objects.filter(Q(url__icontains=target_url))
        for da in all_cookie_url:
            global cookies
            cookies = da.url

        if cookies == target_url:
            print "updateeeeeeeee"
            cookie_db.objects.filter(Q(url__icontains=target_url)).update(cookie=target_cookies)
            return HttpResponseRedirect("/webscanners/")
        else:
            data_dump = cookie_db(url=target_url,
                                  cookie=target_cookies)
            data_dump.save()
            return HttpResponseRedirect("/webscanners/")

    return render(request, 'cookie_add.html')


def arachni_list_vuln(request):
    """
    Arachni Vulnerability List
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    arachni_all_vul = arachni_scan_result_db.objects.filter(
        scan_id=scan_id).values('name',
                                'severity',
                                'vuln_color',
                                'scan_id').distinct()

    return render(request,
                  'arachni_list_vuln.html',
                  {'arachni_all_vul': arachni_all_vul,
                   'scan_id': scan_id})


def arachni_scan_list(request):
    """
    Arachni Scan List.
    :param request:
    :return:
    """
    all_arachni_scan = arachni_scan_db.objects.all()

    return render(request,
                  'arachni_scan_list.html',
                  {'all_arachni_scan': all_arachni_scan})


def arachni_vuln_data(request):
    """
    Arachni Vulnerability Data.
    :param request:
    :return:
    """
    if request.method == 'GET':
        vuln_id = request.GET['vuln_id']
    else:
        vuln_id = None
    vuln_data = arachni_scan_result_db.objects.filter(vuln_id=vuln_id)

    return render(request,
                  'arachni_vuln_data.html',
                  {'vuln_data': vuln_data, })


def arachni_vuln_out(request):
    """
    Arachni Vulnerability details.
    :param request:
    :return:
    """
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        name = request.GET['scan_name']
    if request.method == "POST":
        false_positive = request.POST.get('false')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        arachni_scan_result_db.objects.filter(vuln_id=vuln_id,
                                              scan_id=scan_id).update(false_positive=false_positive)
        return HttpResponseRedirect(
            '/webscanners/arachni_vuln_out/?scan_id=%s&scan_name=%s' % (scan_id, vuln_name))

    vuln_data = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                      name=name,
                                                      false_positive='No')
    false_data = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                       name=name,
                                                       false_positive='Yes')

    return render(request,
                  'arachni_vuln_out.html',
                  {'vuln_data': vuln_data,
                   'false_data': false_data})


def del_arachni_scan(request):
    """
    Delete Arachni Scans.
    :param request:
    :return:
    """
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        # print "split_lenght", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = arachni_scan_db.objects.filter(scan_id=scan_id
                                                  )
            item.delete()
            item_results = arachni_scan_result_db.objects.filter(scan_id=scan_id)
            item_results.delete()
        messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/webscanners/arachni_scan_list/')


def edit_arachni_vuln(request):
    """
    The funtion Editing Arachni Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    edit_vul_dat = burp_scan_result_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')
    if request.method == 'POST':
        vuln_id = request.POST.get("vuln_id", )
        scan_id = request.POST.get("scan_id", )
        name = request.POST.get("name", )
        severity = request.POST.get("severity", )
        host = request.POST.get("host", )
        path = request.POST.get("path", )
        issuedetail = request.POST.get("issuedetail")
        description = request.POST.get("description", )
        solution = request.POST.get("solution", )
        location = request.POST.get("location", )
        vulnerabilityClassifications = request.POST.get("reference", )
        global vul_col
        if severity == 'High':
            vul_col = "important"
        elif severity == 'Medium':
            vul_col = "warning"
        elif severity == 'Low':
            vul_col = "info"
        else:
            vul_col = "info"
        print "edit_vul :", name

        burp_scan_result_db.objects.filter(vuln_id=vuln_id).update(
            name=name,
            severity_color=vul_col,
            severity=severity,
            host=host,
            path=path,
            location=location,
            issueDetail=issuedetail,
            issueBackground=description,
            remediationBackground=solution,
            vulnerabilityClassifications=vulnerabilityClassifications,
        )

        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/webscanners/burp_vuln_data/?vuln_id=%s" % vuln_id)

    return render(request, 'edit_burp_vuln.html', {'edit_vul_dat': edit_vul_dat})


def arachni_del_vuln(request):
    """
    The function Delete the Arachni Vulnerability.
    :param request:
    :return:
    """
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )

        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_lenght", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = arachni_scan_result_db.objects.filter(vuln_id=vuln_id)
            delete_vuln.delete()
        arachni_all_vul = arachni_scan_result_db.objects.filter(scan_id=un_scanid).values(
            'name',
            'severity',
            'vuln_color'
        ).distinct()
        total_vul = len(arachni_all_vul)
        total_high = len(arachni_all_vul.filter(severity="high"))
        total_medium = len(arachni_all_vul.filter(severity="medium"))
        total_low = len(arachni_all_vul.filter(severity="low"))
        arachni_scan_db.objects.filter(scan_id=un_scanid).update(
            total_vul=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low
        )
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/webscanners/arachni_list_vuln?scan_id=%s" % un_scanid)
