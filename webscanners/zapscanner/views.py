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
import threading
import time
import uuid
from django.contrib import messages
from django.db.models import Q
from django.http import HttpResponseRedirect
from django.shortcuts import render, HttpResponse
from easy_pdf.views import render_to_pdf_response
from selenium import webdriver
from archerysettings.models import zap_settings_db
from projects.models import project_db
from scanners.scanner_plugin.web_scanner import burp_plugin
from scanners.scanner_plugin.web_scanner import zap_plugin
from webscanners.models import zap_scan_results_db, \
    zap_scans_db, \
    cookie_db, excluded_db, \
    burp_scan_db, burp_scan_result_db, \
    task_schedule_db
from background_task import background
from datetime import datetime
from background_task.models import Task
from jiraticketing.models import jirasetting
from archerysettings.models import zap_settings_db
import hashlib


scans_status = None

def launch_zap_scan(target_url, project_id, rescan_id, rescan):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(target_url, project_id, rescan_id, rescan)
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
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


def zap_scan(request):
    """
    The function trigger ZAP scan.
    :param request:
    :return:
    """
    global scans_status
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
            print "Targets -", target
            thread = threading.Thread(
                target=launch_zap_scan,
                args=(target, project_id, rescan_id, rescan))
            thread.daemon = True
            thread.start()

        # launch_zap_scan(target_url, project_id)
        if scans_status == '100':
            scans_status = "0"
        else:
            return HttpResponse(status=200)
        return HttpResponse(status=200)

    return render(request,
                  'zapscanner/zap_scan.html')


@background(schedule=60)
def task(target_url, project_id, scanner):
    """
    :param target_url:
    :param project_id:
    :param scanner:
    :return:
    """
    rescan_id = ''
    rescan = 'No'
    target__split = target_url.split(',')
    split_length = target__split.__len__()
    for i in range(0, split_length):
        target = target__split.__getitem__(i)
        if scanner == 'zap_scan':
            thread = threading.Thread(
                target=launch_zap_scan,
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


def zap_scan_task_launch(request):
    """
    :param request:
    :return:
    """
    if request.method == 'GET':
        task_time = request.GET['time']

        t = Task.objects.all()
        # t.delete()
        print task_time

        for ta in t:
            print ta.run_at
            print ta.id

    return HttpResponse(status=200)


def zap_scan_schedule(request):
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

    return render(request, 'zapscanner/zap_scan_schedule.html',
                  {'all_scans_db': all_scans_db,
                   'all_scheduled_scans': all_scheduled_scans}
                  )


def del_zap_scan_schedule(request):
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
        print "split_length", split_length
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
            target=launch_zap_scan,
            args=(scan_url, project_id, rescan_id, rescan))
        thread.daemon = True
        thread.start()
        messages.add_message(request, messages.SUCCESS, 'Re-Scan Launched')

    return HttpResponseRedirect('/zapscanner/zap_scan_list/')


def zap_scan_list(request):
    """
    The function listing all ZAP Web scans.
    :param request:
    :return:
    """
    all_scans = zap_scans_db.objects.filter(rescan='No')
    rescan_all_scans = zap_scans_db.objects.filter(rescan='Yes')

    return render(request,
                  'zapscanner/zap_scan_list.html',
                  {'all_scans': all_scans,
                   'rescan_all_scans': rescan_all_scans,
                   })


def zap_list_vuln(request):
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
        scan_id=scan_id, vuln_status='Open').values(
        'name',
        'risk',
        'vuln_color',
        'scan_id').distinct()

    zap_all_close_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_id, vuln_status='Close').values(
        'name',
        'risk',
        'vuln_color',
        'scan_id').distinct()

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
    jira_url = None
    jira = jirasetting.objects.all()
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
            vuln_id=vuln_id,
            scan_id=scan_id).update(false_positive=false_positive,
                                    vuln_status=vuln_status)
        if false_positive == 'Yes':
            vuln_info = zap_scan_results_db.objects.filter(scan_id=scan_id, vuln_id=vuln_id)
            for vi in vuln_info:
                name = vi.name
                url = vi.url
                risk = vi.risk
                dup_data = name + url + risk
                false_positive_hash = hashlib.sha256(dup_data).hexdigest()
                zap_scan_results_db.objects.filter(
                    vuln_id=vuln_id,
                    scan_id=scan_id).update(false_positive=false_positive,
                                            vuln_status=vuln_status,
                                            false_positive_hash=false_positive_hash
                                            )

        messages.add_message(request,
                             messages.SUCCESS,
                             'Vulnerability Status Changed')
        return HttpResponseRedirect(
            '/zapscanner/zap_vuln_details/?scan_id=%s&scan_name=%s' % (
                scan_id,
                vuln_name
            )
        )
    zap_all_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_id,
        false_positive='No',
        name=scan_name,
        vuln_status='Open'
    )

    zap_all_close_vul = zap_scan_results_db.objects.filter(
        scan_id=scan_id,
        false_positive='No',
        name=scan_name,
        vuln_status='Closed'
    ).order_by('name')

    zap_all_false_vul = zap_scan_results_db.objects.filter(
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
    zap_api_key = ''
    zap_hosts = None
    zap_ports = None

    all_zap = zap_settings_db.objects.all()
    for zap in all_zap:
        # global zap_api_key, zap_hosts, zap_ports
        zap_api_key = zap.zap_api
        zap_hosts = zap.zap_url
        zap_ports = zap.zap_port

    return render(request,
                  'zapscanner/zap_settings_form.html',
                  {
                      'zap_apikey': zap_api_key,
                      'zap_host': zap_hosts,
                      'zap_port': zap_ports,
                  }
                  )


def zap_setting_update(request):
    """
    The function Update the ZAP settings.
    :param request:
    :return:
    """
    # Load ZAP setting function
    # save_setting = save_settings.SaveSettings(setting_file)

    if request.method == 'POST':
        apikey = request.POST.get("apikey", )
        zaphost = request.POST.get("zappath", )
        port = request.POST.get("port", )
        save_data = zap_settings_db(
            zap_url=zaphost,
            zap_port=port,
            zap_api=apikey
        )
        save_data.save()

        return HttpResponseRedirect('/webscanners/setting/')

    messages.add_message(request,
                         messages.SUCCESS,
                         'ZAP Setting Updated ')

    return render(request,
                  'zapscanner/zap_settings_form.html')


def zap_scan_table(request):
    """
    Scan Table.
    :param request:
    :return:
    """
    all_scans = zap_scans_db.objects.all()

    return render(request, 'zapscanner/zap_scan_table.html', {'all_scans': all_scans})


def del_zap_scan(request):
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
            print "split_length", split_length
            for i in range(0, split_length):
                target = target_split.__getitem__(i)

                item = zap_scans_db.objects.filter(scan_scanid=target,
                                                   )
                item.delete()
                item_results = zap_scan_results_db.objects.filter(scan_id=target,
                                                                  )
                item_results.delete()
                messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
            return HttpResponseRedirect('/zapscanner/zap_scan_list/')
    except Exception as e:
        print "Error Got !!!"


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

    return HttpResponseRedirect('/zapscanner/')


def cookies_list(request):
    """

    :param request:
    :return:
    """
    all_cookies = cookie_db.objects.all()

    return render(request, 'cookies_list.html', {'all_cookies': all_cookies})


def del_cookies(request):
    if request.method == 'POST':
        # cookie_id = request.POST.get('id')
        cookie_url = request.POST.get('url')
        cookies_item = str(cookie_url)
        cooki_split = cookies_item.replace(" ", "")
        target_split = cooki_split.split(',')
        split_length = target_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            cookies_target = target_split.__getitem__(i)
            print(cookies_target)
            del_cookie = cookie_db.objects.filter(url=cookies_target)
            del_cookie.delete()
            zap_plugin.zap_replacer(target_url=cookies_target)
        return HttpResponseRedirect('/zapscanner/')

    return render(request, 'cookies_list.html')


def sel_login(request):
    """
    Lgoin perfrom using Selenium.
    :param request:
    :return:
    """
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

            # cookie_save = cookie_db(url=new_uri, cookie=cookie_data)
            # cookie_save.save()

            # target_url = request.POST.get('url')
            # target_cookies = request.POST.get('cookies')
            print(cookie_data)
            all_cookie_url = cookie_db.objects.filter(Q(url__icontains=new_uri))
            for da in all_cookie_url:
                global cookies
                cookies = da.url

            if cookies == new_uri:
                cookie_db.objects.filter(Q(url__icontains=new_uri)).update(cookie=cookie_data)
                return HttpResponseRedirect("/zapscanner/")
            else:
                data_dump = cookie_db(url=new_uri,
                                      cookie=cookie_data)
                data_dump.save()
                return HttpResponseRedirect("/zapscanner/")
        messages.add_message(request, messages.SUCCESS, 'Cookies stored')

        return HttpResponseRedirect('/zapscanner/')
    return render(request, 'webscanner.html')


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


def exluded_url_list(request):
    """

    :param request:
    :return:
    """
    all_excluded_url = excluded_db.objects.all()

    if request.method == 'POST':
        exclude_url = request.POST.get('exclude_url')
        exluded_item = str(exclude_url)
        exclude_split = exluded_item.replace(" ", "")
        target_split = exclude_split.split(',')
        split_length = target_split.__len__()
        for i in range(0, split_length):
            exclude_target = target_split.__getitem__(i)

            del_excluded = excluded_db.objects.filter(exclude_url=exclude_target)
            del_excluded.delete()

        return HttpResponseRedirect('/zapscanner/excluded_url_list')

    return render(request, 'excludedurl_list.html', {'all_excluded_url': all_excluded_url})


def edit_zap_vuln(request):
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
        return HttpResponseRedirect("/zapscanner/zap_vuln_check/?vuln_id=%s" % vuln_id)
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']
    else:
        id_vul = ''
    edit_vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'zapscanner/edit_zap_vuln.html', {'edit_vul_dat': edit_vul_dat})


def del_zap_vuln(request):
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
        print "split_length", split_length
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

        return HttpResponseRedirect("/zapscanner/zap_list_vuln/?scan_id=%s" % un_scanid)


def zap_vuln_check(request):
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

    return render(request, 'zapscanner/zap_vuln_check.html', {'vul_dat': vul_dat})


def edit_zap_vuln_check(request):
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

    return render(request, 'zapscanner/edit_zap_vuln_check.html', {'edit_vul_dat': edit_vul_dat})


def add_zap_vuln(request):
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
            return HttpResponseRedirect("/zapscanner/web_vuln_list/?scan_id=%s" % scan_id)

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

            return HttpResponseRedirect("/zapscanner/burp_vuln_list?scan_id=%s" % scan_id)

    return render(request, 'zapscanner/add_zap_vuln.html', {'scan_id': scan_id, 'scanners': scanners})


def create_zap_vuln(request):
    """
    Add vulnerabilities.
    :param request:
    :return:
    """
    return render(request, 'zapscanner/add_zap_vuln.html')


def zap_scan_pdf_gen(request):
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
                                      template=str('zapscanner/zap_scan_pdf_gen.html'),
                                      download_filename=None,
                                      content_type='application/pdf',
                                      context={'all_scan': all_scan,
                                               'vuln_scan': vuln_scan,
                                               'scan_url': scan_url,
                                               'zap_all_vul': zap_all_vul})
