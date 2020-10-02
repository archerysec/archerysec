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
import threading
import time
import uuid
from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import render, HttpResponse
# from easy_pdf.views import render_to_pdf_response
from selenium import webdriver
from scanners.scanner_plugin.web_scanner import zap_plugin
from webscanners.models import zap_scan_results_db, \
    zap_scans_db, \
    cookie_db, excluded_db, \
    burp_scan_db, burp_scan_result_db
from datetime import datetime
from jiraticketing.models import jirasetting
from archerysettings.models import zap_settings_db
import hashlib
from webscanners.resources import ZapResource
from notifications.signals import notify
from notifications.models import Notification
from django.core.mail import send_mail
from django.conf import settings
from archerysettings.models import email_db
import ast
from django.urls import reverse

scans_status = None
to_mail = ''
scan_id = None
scan_name = None


def email_notify(user, subject, message):
    global to_mail
    all_email = email_db.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb='Email Settings Not Configured')


def email_sch_notify(subject, message):
    global to_mail
    all_email = email_db.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        print(e)


def launch_zap_scan(target_url, project_id, rescan_id, rescan, scan_id, user):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    username = user.username
    zap_enabled = False
    random_port = '8091'

    all_zap = zap_settings_db.objects.filter(username=username)
    for zap in all_zap:
        zap_enabled = zap.enabled

    if zap_enabled is False:
        print("started local instence")
        random_port = zap_plugin.zap_local()

    for i in range(0, 100):
        while True:
            try:
                # Connection Test
                zap_connect = zap_plugin.zap_connect(random_port, username=username)
                zap_connect.spider.scan(url=target_url)
            except Exception as e:
                print("ZAP Connection Not Found, re-try after 5 sec")
                time.sleep(5)
                continue
            break

    zap_plugin.zap_spider_thread(count=20, random_port=random_port, username=username)
    zap_plugin.zap_spider_setOptionMaxDepth(count=5, random_port=random_port, username=username)

    zap_plugin.zap_scan_thread(count=30, random_port=random_port, username=username)
    zap_plugin.zap_scan_setOptionHostPerScan(count=3, random_port=random_port, username=username)

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(target_url, project_id, rescan_id, rescan, random_port=random_port, username=username)
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = zap_scans_db(
            username=username,
            project_id=project_id,
            scan_url=target_url,
            scan_scanid=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            vul_status='0'
        )

        save_all_scan.save()
        notify.send(user, recipient=user, verb='ZAP Scan URL %s Added' % target_url)
    except Exception as e:
        print(e)

    notify.send(user, recipient=user, verb='ZAP Scan Started')
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    notify.send(user, recipient=user, verb='ZAP Scan Spider Completed')
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    zap.zap_scan_status(
        scan_id=zap_scan_id,
        un_scanid=scan_id
    )
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    save_all_vuln = zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        username=username,
    )
    print(save_all_vuln)
    all_zap_scan = zap_scans_db.objects.filter(username=username)

    total_vuln = ''
    total_high = ''
    total_medium = ''
    total_low = ''
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    if zap_enabled is False:
        zap.zap_shutdown()

    notify.send(user, recipient=user, verb='ZAP Scan URL %s Completed' % target_url)

    subject = 'Archery Tool Scan Status - ZAP Scan Completed'
    message = 'ZAP Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (target_url, total_vuln, total_high, total_medium, total_low)

    email_notify(user=user, subject=subject, message=message)


def launch_schudle_zap_scan(target_url, project_id, rescan_id, rescan, scan_id):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    random_port = '8090'

    # Connection Test
    zap_connect = zap_plugin.zap_connect(random_port, username='')

    try:
        zap_connect.spider.scan(url=target_url)

    except Exception:
        subject = 'ZAP Connection Not Found'
        message = 'ZAP Scanner failed due to setting not found '

        email_sch_notify(subject=subject, message=message)
        print("ZAP Connection Not Found")
        return HttpResponseRedirect(reverse('webscanners:index'))

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(target_url, project_id, rescan_id, rescan, random_port=random_port)
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = zap_scans_db(
            project_id=project_id,
            scan_url=target_url,
            scan_scanid=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            vul_status='0'
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
    zap.zap_scan_status(
        scan_id=zap_scan_id,
        un_scanid=scan_id
    )
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        username=''
    )
    all_zap_scan = zap_scans_db.objects.all()

    total_vuln = ''
    total_high = ''
    total_medium = ''
    total_low = ''
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    subject = 'Archery Tool Scan Status - ZAP Scan Completed'
    message = 'ZAP Scanner has completed the scan ' \
              '  %s <br> Total: %s <br>High: %s <br>' \
              'Medium: %s <br>Low %s' % (target_url, total_vuln, total_high, total_medium, total_low)

    email_sch_notify(subject=subject, message=message)


def zap_scan(request):
    """
    The function trigger ZAP scan.
    :param request:
    :return:
    """
    global scans_status
    user = request.user
    if request.POST.get("url", ):
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        rescan_id = None
        rescan = 'No'
        target_item = str(target_url)
        value = target_item.replace(" ", "")
        target__split = value.split(',')
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_zap_scan,
                args=(target, project_id, rescan_id, rescan, scan_id, user))
            thread.daemon = True
            thread.start()
            time.sleep(10)
        if scans_status == '100':
            scans_status = "0"
        else:
            return HttpResponse(status=200)
        return HttpResponse(status=200)

    return render(request,
                  'zapscanner/zap_scan_list.html')


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
        scan_id = uuid.uuid4()
        thread = threading.Thread(
            target=launch_zap_scan,
            args=(scan_url, project_id, rescan_id, rescan, scan_id))
        thread.daemon = True
        thread.start()

    return HttpResponseRedirect(reverse('zapscanner:zap_scan_list'))


def zap_scan_list(request):
    """
    The function listing all ZAP Web scans.
    :param request:
    :return:
    """
    username = request.user.username
    all_scans = zap_scans_db.objects.filter(rescan='No', username=username)
    rescan_all_scans = zap_scans_db.objects.filter(rescan='Yes', username=username)
    zap_scan_result = zap_scan_results_db.objects.filter(username=username)

    all_notify = Notification.objects.unread()

    return render(request,
                  'zapscanner/zap_scan_list.html',
                  {'all_scans': all_scans,
                   'rescan_all_scans': rescan_all_scans,
                   'zap_scan_result': zap_scan_result,
                   'message': all_notify
                   })


def zap_list_vuln(request):
    """
    The function returning all Web Application Vulnerability.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    zap_all_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_id, username=username).values(
        'name',
        'risk',
        'vuln_color',
        'vuln_status',
        'scan_id').distinct().exclude(vuln_status='Duplicate')

    zap_all_close_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_id, username=username).values(
        'name',
        'risk',
        'vuln_color',
        'vuln_status',
        'scan_id').distinct().exclude(vuln_status='Duplicate')

    return render(request,
                  'zapscanner/zap_list_vuln.html',
                  {'zap_all_vul': zap_all_vul,
                   'scan_id': scan_id,
                   'zap_all_close_vul': zap_all_close_vul

                   })


def zap_vuln_details(request):
    """
    The function retiring Web Application vulnerabilities details.
    :param request:
    :return:
    """
    username = request.user.username
    global scan_id, scan_name
    jira_url = None
    jira = jirasetting.objects.filter(username=username)
    for d in jira:
        jira_url = d.jira_server

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scan_name = request.GET['scan_name']
    if request.method == "POST":
        false_positive = request.POST.get('false')
        vuln_status = request.POST.get('status')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        zap_scan_results_db.objects.filter(
            vuln_id=vuln_id, username=username,
            scan_id=scan_id).update(false_positive=false_positive,
                                    vuln_status=vuln_status)
        if false_positive == 'Yes':
            vuln_info = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                url = vi.url
                risk = vi.risk
                dup_data = name + url + risk
                false_positive_hash = hashlib.sha256(dup_data.encode('utf-8')).hexdigest()
                zap_scan_results_db.objects.filter(username=username,
                                                   vuln_id=vuln_id,
                                                   scan_id=scan_id).update(false_positive=false_positive,
                                                                           vuln_status='Close',
                                                                           false_positive_hash=false_positive_hash
                                                                           )

        zap_all_vul = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id, false_positive='No',
                                                         vuln_status='Open')

        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))
        total_info = len(zap_all_vul.filter(risk="Informational"))
        total_duplicate = len(zap_all_vul.filter(vuln_duplicate='Yes'))
        total_vul = total_high + total_medium + total_low + total_info

        zap_scans_db.objects.filter(scan_scanid=scan_id, username=username) \
            .update(total_vul=total_vul,
                    high_vul=total_high,
                    medium_vul=total_medium,
                    low_vul=total_low,
                    info_vul=total_info,

                    )

        # messages.add_message(request,
        #                      messages.SUCCESS,
        #                      'Vulnerability Status Changed')
        return HttpResponseRedirect(
            reverse('zapscanner:zap_vuln_details') + '?scan_id=%s&scan_name=%s' % (
                scan_id,
                vuln_name
            )
        )
    zap_all_vul = zap_scan_results_db.objects.filter(
        username=username,
        scan_id=scan_id,
        false_positive='No',
        name=scan_name,
        vuln_status='Open'
    )

    zap_all_close_vul = zap_scan_results_db.objects.filter(
        username=username,
        scan_id=scan_id,
        false_positive='No',
        name=scan_name,
        vuln_status='Closed'
    ).order_by('name')

    zap_all_false_vul = zap_scan_results_db.objects.filter(
        username=username,
        scan_id=scan_id,
        name=scan_name,
        false_positive='Yes').order_by('name')

    return render(request,
                  'zapscanner/zap_vuln_details.html',
                  {'zap_all_vul': zap_all_vul,
                   'scan_vul': scan_id,
                   'zap_all_false_vul': zap_all_false_vul,
                   'jira_url': jira_url,
                   'zap_all_close_vul': zap_all_close_vul
                   })


def zap_settings(request):
    """
    The function calling ZAP Scanner setting page.
    :param request:
    :return:
    """
    username = request.user.username
    zap_api_key = ''
    zap_hosts = None
    zap_ports = None
    zap_enabled = False

    all_zap = zap_settings_db.objects.filter(username=username)
    for zap in all_zap:
        zap_api_key = zap.zap_api
        zap_hosts = zap.zap_url
        zap_ports = zap.zap_port
        zap_enabled = zap.enabled

    if zap_enabled:
        zap_enabled = 'True'
    else:
        zap_enabled = 'False'

    return render(request,
                  'zapscanner/zap_settings_form.html',
                  {
                      'zap_apikey': zap_api_key,
                      'zap_host': zap_hosts,
                      'zap_port': zap_ports,
                      'zap_enabled': zap_enabled
                  }
                  )


def zap_setting_update(request):
    """
    The function Update the ZAP settings.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':

        all_zap = zap_settings_db.objects.filter(username=username)
        all_zap.delete()

        if request.POST.get("zap_enabled") == 'on':
            zap_enabled = True
        else:
            zap_enabled = False

        apikey = request.POST.get("apikey", )
        zaphost = request.POST.get("zappath", )
        port = request.POST.get("port", )
        save_data = zap_settings_db(
            username=username,
            zap_url=zaphost,
            zap_port=port,
            zap_api=apikey,
            enabled=zap_enabled
        )
        save_data.save()

        return HttpResponseRedirect(reverse('webscanners:setting'))

    # messages.add_message(request,
    #                      messages.SUCCESS,
    #                      'ZAP Setting Updated ')

    return render(request,
                  'zapscanner/zap_settings_form.html')


def del_zap_scan(request):
    """
    The function deleting scans from ZAP scans.
    :param request:
    :return:
    """
    username = request.user.username
    try:
        if request.method == 'POST':
            item_id = request.POST.get("scan_scanid")
            scan_item = str(item_id)
            ip = scan_item.replace(" ", "")
            target_split = ip.split(',')
            split_length = target_split.__len__()
            for i in range(0, split_length):
                target = target_split.__getitem__(i)
                item_results = zap_scan_results_db.objects.filter(username=username, scan_id=target,
                                                                  )
                item_results.delete()

                item = zap_scans_db.objects.filter(username=username, scan_scanid=target,
                                                   )
                item.delete()
                # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
            return HttpResponseRedirect(reverse('webscanners:index'))
    except Exception as e:
        print("Error Got !!!")


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
        for i in range(0, split_length):
            cookies_target = target_split.__getitem__(i)
            print(cookies_target)
            del_cookie = cookie_db.objects.filter(username=username, url=cookies_target)
            del_cookie.delete()
            zap_plugin.zap_replacer(target_url=cookies_target, random_port='8090')
        return HttpResponseRedirect(reverse('webscanners:index'))

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
    # print(url_da)
    if action_vul == "open_page":
        global driver
        driver = webdriver.Firefox()
        slem(driver, url_da)
    elif action_vul == "save_cookie":
        save_cookie(driver)
        read_f = open('cookies.txt', 'r')

        for cookie_data in read_f:
            # cookie_save.save()
            # target_cookies = request.POST.get('cookies')
            print(cookie_data)
            all_cookie_url = cookie_db.objects.filter(Q(url__icontains=new_uri, username=username))
            for da in all_cookie_url:
                global cookies
                cookies = da.url

            if cookies == new_uri:
                cookie_db.objects.filter(Q(url__icontains=new_uri, username=username)).update(cookie=cookie_data)
                return HttpResponseRedirect(reverse('webscanners:index'))
            else:
                data_dump = cookie_db(url=new_uri, username=username, cookie=cookie_data)
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
    exclude_save = excluded_db(username=username, exclude_url=exclud)
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


def del_zap_vuln(request):
    """
    Delete Vulnerability from database.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = zap_scan_results_db.objects.filter(username=username, vuln_id=vuln_id)
            delete_vuln.delete()
        zap_all_vul = zap_scan_results_db.objects.filter(username=username, scan_id=un_scanid).values('name', 'risk',
                                                                                                      'vuln_color').distinct()
        total_vul = len(zap_all_vul)
        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))

        zap_scans_db.objects.filter(username=username, scan_scanid=un_scanid).update(total_vul=total_vul,
                                                                                     high_vul=total_high,
                                                                                     medium_vul=total_medium,
                                                                                     low_vul=total_low)
        # messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect(reverse('zapscanner:zap_list_vuln') + '?scan_id=%s' % un_scanid)


def zap_vuln_check(request):
    """
    Calling vulnerability Data list.
    :param request:
    :return:
    """
    username = request.user.username
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    vul_dat = zap_scan_results_db.objects.filter(username=username, vuln_id=id_vul).order_by('vuln_id')

    full_data = []
    for data in vul_dat:
        evi = data.evidence
        try:
            evi_data = ast.literal_eval(evi)
            for evidence in evi_data:
                for key, value in evidence.items():
                    if key == 'evidence':
                        key = 'Evidence'

                    if key == 'attack':
                        key = 'Attack'

                    if key == 'uri':
                        key = 'URI'

                    if key == 'method':
                        key = 'Method'

                    if key == 'param':
                        key = 'Parameter'

                    instance = key + ': ' + value

                    full_data.append(instance)
        except Exception as e:
            full_data = 'NA'
            print(e)

    return render(request, 'zapscanner/zap_vuln_check.html',
                  {'vul_dat': vul_dat,
                   'evi': full_data
                   })


def zap_scan_pdf_gen(request):
    """
    Generate Report in PDF format.
    :param request:
    :return:
    """
    username = request.user.username
    all_scan = zap_scans_db.objects.filter(username=username)

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")
        vuln_scan = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        zap_all_vul = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id).values('name',
                                                                                                    'risk',
                                                                                                    'vuln_color',
                                                                                                    'scan_id').distinct()

        return render_to_pdf_response(request,
                                      template=str('zapscanner/zap_scan_pdf_gen.html'),
                                      download_filename=None,
                                      content_type='application/pdf',
                                      context={'all_scan': all_scan,
                                               'vuln_scan': vuln_scan,
                                               'scan_url': scan_url,
                                               'zap_all_vul': zap_all_vul,
                                               # 'evi': evi_list

                                               })


def export(request):
    """
    :param request:
    :return:
    """
    username = request.user.username

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        zap_resource = ZapResource()
        queryset = zap_scan_results_db.objects.filter(username=username, scan_id=scan_id)
        dataset = zap_resource.export(queryset)
        if report_type == 'csv':
            response = HttpResponse(dataset.csv, content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="%s.csv"' % scan_id
            return response
        if report_type == 'json':
            response = HttpResponse(dataset.json, content_type='application/json')
            response['Content-Disposition'] = 'attachment; filename="%s.json"' % scan_id
            return response
        if report_type == 'yaml':
            response = HttpResponse(dataset.yaml, content_type='application/x-yaml')
            response['Content-Disposition'] = 'attachment; filename="%s.yaml"' % scan_id
            return response
