from __future__ import unicode_literals

from django.shortcuts import render, render_to_response, HttpResponse

from webscanners.models import zap_scan_results_db, zap_scans_db, zap_spider_db, zap_spider_results, cookie_db, \
    excluded_db, \
    burp_scan_db, burp_scan_result_db, email_config_db, arachni_scan_db, arachni_scan_result_db
from django.db.models import Q
import os
import json
from zapv2 import ZAPv2
import time
from scanners import zapscanner
from stronghold.decorators import public
from django.contrib import auth
from django.views.decorators.csrf import csrf_protect
from django.http import HttpResponseRedirect
import uuid
from selenium import webdriver
from django.contrib import messages
import ast
from django.core import signing
from projects.models import project_db
import datetime
from networkscanners.models import scan_save_db
from django.conf import settings
from easy_pdf.views import PDFTemplateView, render_to_pdf_response
import xml.etree.ElementTree as ET
from projects.models import project_db
from django.contrib.auth.models import User

from burp_scan import burp_scans
from itertools import chain
import email_notification
import zap_xml_parser
import arachni_xml_parser

api_key_path = os.getcwd() + '/' + 'apidata.json'

spider_status = "0"
scans_status = "0"
spider_alert = []
target_url = []
driver = []
new_uri = []
cookies = []
excluded_url = []
vul_col = []
note = []
rtt = []
tags = []
timestamp = []
responseHeader = []
requestBody = []
responseBody = []
requestHeader = []
cookieParams = []
res_type = []
res_id = []

alert = []
project_id = None
target_url = None
scan_ip = None
burp_status = 0

serialNumber = []
types = []
name = []
host = []
path = []
location = []
severity = []
confidence = []
issueBackground = []
remediationBackground = []
references = []
vulnerabilityClassifications = []
issueDetail = []
requestresponse = []
vuln_id = []
methods = []
dec_res = []
dec_req = []
decd_req = []
scanner = []
all_scan_url = []
all_url_vuln = []


# Login View
@public
@csrf_protect
def login(request):
    c = {}
    c.update(request)
    return render(request, "login.html", c)


@public
def auth_view(request):
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
    auth.logout(request)
    return render_to_response("logout.html")

@public
def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')
        user = User.objects.create_user(username, email, password)
        user.save()
        return HttpResponseRedirect('/login/')

    return render(request, 'signup.html')


def loggedin(request):
    return render(request, 'webscanner.html')


def invalid_login():
    return render_to_response('invalid_login.html')


def launch_web_scan(target_url, project_id):
    try:
        with open(api_key_path, 'r+') as f:
            data = json.load(f)
            lod_apikey = data['zap_api_key']
            apikey = signing.loads(lod_apikey)
            zapath = data['zap_path']
            zap_port = data['zap_port']
    except Exception as e:
        print e

    # Define settings to ZAP Proxy
    zap = ZAPv2(apikey=apikey,
                proxies={'http': zapath + ':' + zap_port, 'https': zapath + ':' + zap_port})

    """
        Zap scan start
    """
    # try:
    #     # ZAP launch function
    #     zapscanner.start_zap()
    #
    # except Exception as e:
    #     print e
    #     print "ZAP Failed.............."
    #     print "ZAP Restarting"
    #
    # time.sleep(15)

    # Get Excluded URL from excluded_db models
    try:
        all_excluded = excluded_db.objects.filter(Q(exclude_url__icontains=target_url))

        for data in all_excluded:
            global excluded_url
            excluded_url = data.exclude_url
            print "excluded url ", excluded_url

        print "Excluded url ", excluded_url

        # Excluding URL from scans in zap API
        url_exclude = zap.spider.exclude_from_scan(regex=excluded_url)

        print "URL Excluded:", url_exclude
    except Exception as e:
        print "ZAP Failed.............."
        print "ZAP Restarting"

    all_cookie = cookie_db.objects.filter(Q(url__icontains=target_url))
    for da in all_cookie:
        global cookies
        cookies = da.cookie
        print da.url
        print "Cookies from database:", cookies
    try:
        remove_cookie = zap.replacer.remove_rule(target_url)
    except Exception as e:
        print e
    print "Remove Cookie :", remove_cookie
    # Adding cookies value
    try:
        cookie_add = zap.replacer.add_rule(apikey=apikey, description=target_url, enabled="true",
                                           matchtype='REQ_HEADER', matchregex="false", replacement=cookies,
                                           matchstring="Cookie", initiators="")

        print "Cookies Added :", cookie_add
    except Exception as e:
        print e

    zap.ajaxSpider.scan(target_url)
    try:

        scanid = zap.spider.scan(target_url)
        save_all = zap_spider_db(spider_url=target_url, spider_scanid=scanid)
        save_all.save()
    except Exception as e:
        print e

    try:
        zap.spider.set_option_thread_count(apikey=apikey, integer='30')
    except Exception as e:
        print e

    try:
        while (int(zap.spider.status(scanid)) < 100):
            global spider_status
            spider_status = zap.spider.status(scanid)
            print "Spider progress", spider_status
            time.sleep(5)
    except Exception as e:
        print e

    spider_status = "100"

    spider_res_out = zap.spider.results(scanid)
    data_out = ("\n".join(map(str, spider_res_out)))
    print data_out

    print 'Spider Completed------'
    print 'Target :', target_url
    global spider_alert
    spider_alert = "Spider Completed"

    time.sleep(5)

    print 'Scanning Target %s' % target_url

    """
        ZAP Scan trigger on target_url
    """
    try:
        scan_scanid = zap.ascan.scan(target_url)
    except Exception as e:
        print e

    un_scanid = uuid.uuid4()
    date_time = datetime.datetime.now()
    try:
        save_all_scan = zap_scans_db(project_id=project_id, scan_url=target_url, scan_scanid=un_scanid,
                                     date_time=date_time)
        save_all_scan.save()
    except Exception as e:
        print e

    try:
        while (int(zap.ascan.status(scan_scanid)) < 100):
            print 'ZAP Scan Status  %: ' + zap.ascan.status(scan_scanid)
            global scans_status
            scans_status = zap.ascan.status(scan_scanid)
            zap_scans_db.objects.filter(scan_scanid=un_scanid).update(vul_status=scans_status)
            time.sleep(5)
    except Exception as e:
        print e

    # Save Vulnerability in database
    scans_status = "100"
    zap_scans_db.objects.filter(scan_scanid=un_scanid).update(vul_status=scans_status)
    print target_url
    time.sleep(5)
    all_vuln = zap.core.alerts(target_url)

    for vuln in all_vuln:
        vuln_id = uuid.uuid4()
        confidence = vuln['confidence']
        wascid = vuln['wascid']
        cweid = vuln['cweid']
        risk = vuln['risk']
        reference = vuln['reference']
        url = vuln['url']
        name = vuln['name']
        solution = vuln['solution']
        param = vuln['param']
        evidence = vuln['evidence']
        sourceid = vuln['sourceid']
        pluginId = vuln['pluginId']
        other = vuln['other']
        attack = vuln['attack']
        messageId = vuln['messageId']
        method = vuln['method']
        alert = vuln['alert']
        ids = vuln['id']
        description = vuln['description']
        false_positive = 'No'

        global vul_col

        if risk == 'High':
            vul_col = "important"
        elif risk == 'Medium':
            vul_col = "warning"
        elif risk == 'Low':
            vul_col = "info"
        else:
            vul_col = "info"

        # date_time = datetime.datetime.now()

        dump_all = zap_scan_results_db(vuln_id=vuln_id, vuln_color=vul_col, scan_id=un_scanid,
                                       project_id=project_id,
                                       confidence=confidence, wascid=wascid,
                                       cweid=cweid,
                                       risk=risk, reference=reference, url=url, name=name,
                                       solution=solution,
                                       param=param, evidence=evidence, sourceid=sourceid, pluginId=pluginId,
                                       other=other, attack=attack, messageId=messageId, method=method,
                                       alert=alert, ids=ids, description=description,
                                       false_positive=false_positive)
        dump_all.save()

    time.sleep(5)

    zap_all_vul = zap_scan_results_db.objects.filter(scan_id=un_scanid).values('name', 'risk', 'vuln_color').distinct()

    total_vul = len(zap_all_vul)
    total_high = len(zap_all_vul.filter(risk="High"))
    total_medium = len(zap_all_vul.filter(risk="Medium"))
    total_low = len(zap_all_vul.filter(risk="Low"))

    zap_scans_db.objects.filter(scan_scanid=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                              medium_vul=total_medium, low_vul=total_low)

    spider_alert = "Scan Completed"

    time.sleep(10)

    print un_scanid

    zap_web_all = zap_scan_results_db.objects.filter(scan_id=un_scanid)
    for m in zap_web_all:
        msg_id = m.messageId
        request_response = zap.core.message(id=msg_id)
        ja_son = json.dumps(request_response)
        ss = ast.literal_eval(ja_son)

        for key, value in ss.viewitems():
            global note
            if key == "note":
                note = value
            global rtt
            if key == "rtt":
                rtt = value
            global tags
            if key == "tags":
                tags = value
            global timestamp
            if key == "timestamp":
                timestamp = value
            global responseHeader
            if key == "responseHeader":
                responseHeader = value
            global requestBody
            if key == "requestBody":
                requestBody = value
            global responseBody
            if key == "responseBody":
                responseBody = value
            global requestHeader
            if key == "requestHeader":
                requestHeader = value
            global cookieParams
            if key == "cookieParams":
                cookieParams = value
            global res_type
            if key == "type":
                res_type = value
            global res_id
            if key == "id":
                res_id = value

        zap_scan_results_db.objects.filter(messageId=msg_id).update(note=note, rtt=rtt, tags=tags,
                                                                    timestamp=timestamp,
                                                                    responseHeader=responseHeader,
                                                                    requestBody=requestBody,
                                                                    responseBody=responseBody,
                                                                    requestHeader=requestHeader,
                                                                    cookieParams=cookieParams,
                                                                    res_type=res_type,
                                                                    res_id=res_id)

    #zapscanner.stop_zap()
    try:
        email_notification.email_notify()
    except Exception as e:
        print e

    return HttpResponse(status=201)


def index(request):
    all_urls = zap_spider_db.objects.all()
    all_scans = zap_scans_db.objects.all()
    all_spider_results = zap_spider_results.objects.all()
    all_excluded_url = excluded_db.objects.all()
    all_cookies = cookie_db.objects.all()

    all_scans_db = project_db.objects.all()

    return render(request, 'webscanner.html',
                  {'all_urls': all_urls, 'spider_status': spider_status, 'scans_status': scans_status,
                   'all_scans': all_scans, 'all_spider_results': all_spider_results, 'spider_alert': spider_alert,
                   'all_excluded_url': all_excluded_url, 'all_cookies': all_cookies, 'all_scans_db': all_scans_db})


def web_scan(request):
    global scans_status
    if request.POST.get("url", ):
        target_url = request.POST.get('url', )
        project_id = request.POST.get('project_id', )

        # while (int(scans_status) < 100):
        #     try:
        #
        #     except Exception as e:
        #         print "---------------------------------"
        # print "scan_status :-----------%s" % scans_status
        launch_web_scan(target_url, project_id)
        if scans_status == '100':

            scans_status = "0"
        else:
            return scans_status
        return HttpResponse(status=201)

    return render(request, 'scan_list.html')


def scan_list(request):
    all_scans = zap_scans_db.objects.all()

    return render(request, 'scan_list.html', {'all_scans': all_scans})


def list_web_vuln(request):
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_id).values('name', 'risk', 'vuln_color',
                                                                             'scan_id').distinct()

    return render(request, 'list_web_vuln.html', {'zap_all_vul': zap_all_vul, 'scan_id': scan_id})


def vuln_details(request):
    if request.method == 'GET':
        scan_vul = request.GET['scan_id']
        scan_name = request.GET['scan_name']

    if request.method == "POST":
        false_positive = request.POST.get('false')
        vuln_id = request.POST.get('vuln_id')
        scan_id = request.POST.get('scan_id')
        vuln_name = request.POST.get('vuln_name')
        zap_scan_results_db.objects.filter(vuln_id=vuln_id,
                                           scan_id=scan_id).update(false_positive=false_positive)
        return HttpResponseRedirect(
            '/webscanners/zap_vul_details/?scan_id=%s&scan_name=%s' % (scan_id, vuln_name))

    zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_vul, false_positive='No', name=scan_name).order_by(
        'name')
    zap_all_false_vul = zap_scan_results_db.objects.filter(scan_id=scan_vul, name=scan_name,
                                                           false_positive='Yes').order_by('name')

    return render(request, 'vuln_details.html',
                  {'zap_all_vul': zap_all_vul, 'scan_vul': scan_vul, 'zap_all_false_vul': zap_all_false_vul})


def setting(request):
    # openvas_set = openvas_info.objects.all()

    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        apikey = data['zap_api_key']

        ov_user = data['open_vas_user']
        ov_pass = data['open_vas_pass']
        ov_ip = data['open_vas_ip']

        lod_ov_user = signing.loads(ov_user)
        lod_ov_pass = signing.loads(ov_pass)
        lod_ov_ip = signing.loads(ov_ip)

        lod_apikey = signing.loads(apikey)
        zapath = data['zap_path']
        zap_port = data['zap_port']

        burp_path = data['burp_path']
        burp_port = data['burp_port']

        email_subject = data['email_subject']
        email_from = data['from_email']
        to_email = data['to_email']

    return render(request, 'setting.html',
                  {'apikey': lod_apikey, 'zapath': zapath, 'zap_port': zap_port,
                   'lod_ov_user': lod_ov_user,
                   'lod_ov_pass': lod_ov_pass,
                   'lod_ov_ip': lod_ov_ip, 'burp_path': burp_path,
                   'burp_port': burp_port,
                   'email_subject': email_subject,
                   'email_from': email_from, 'to_email': to_email})


def zap_setting(request):
    return render(request, 'settingform.html')


def zap_set_update(request):
    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        apikey = data['zap_api_key']
        lod_apikey = signing.loads(apikey)
        zapath = data['zap_path']
        zap_port = data['zap_port']

    if request.method == 'POST':
        apikey = request.POST.get("apikey", )
        zapath = request.POST.get("zappath", )
        port = request.POST.get("port", )
    else:
        apikey = lod_apikey
        zapath = zapath
        port = zap_port

    with open(api_key_path, 'r+') as f:
        sig_apikey = signing.dumps(apikey)
        data = json.load(f)
        data['zap_api_key'] = sig_apikey
        data['zap_path'] = str(zapath)
        data['zap_port'] = port
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()

    messages.add_message(request, messages.SUCCESS, 'ZAP Setting Updated ')

    return render(request, 'settingform.html', )


def email_setting(request):
    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        email_subject = data['email_subject']
        email_from = data['from_email']
        to_email = data['to_email']

    if request.method == 'POST':
        subject = request.POST.get("email_subject")
        from_email = request.POST.get("from_email")
        email_to = request.POST.get("to_email")
    else:
        subject = email_subject
        from_email = email_from
        email_to = to_email

    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        data['email_subject'] = subject
        data['from_email'] = from_email
        data['to_email'] = email_to
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()

    return render(request, 'email_setting_form.html')


def scan_table(request):
    all_scans = zap_scans_db.objects.all()

    return render(request, 'scan_table.html', {'all_scans': all_scans})


def del_scan(request):
    try:
        if request.method == 'POST':
            item_id = request.POST.get("scan_scanid")
            scan_url = request.POST.get("scan_url")

            item = zap_scans_db.objects.filter(scan_scanid=item_id, scan_url=scan_url)
            item.delete()
            item_results = zap_scan_results_db.objects.filter(scan_id=item_id, url=scan_url)
            item_results.delete()
            messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
            return HttpResponseRedirect('/webscanners/scans_list/')
    except Exception as e:
        print "Eroor Got !!!"


def dashboard(request):
    global project_id, target_url, scan_ip, scanner, all_scan_url, all_url_vuln
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
            zap_url_vuln = zap_scans_db.objects.filter(project_id=project_id, scan_url=target_url)

            burp_scan_url = burp_scan_db.objects.filter(project_id=project_id)
            burp_url_vuln = burp_scan_db.objects.filter(project_id=project_id, url=target_url)

            all_scan_url = chain(zap_scan_url, burp_scan_url)
            all_url_vuln = chain(zap_url_vuln, burp_url_vuln)
    except Exception as e:
        print "Error Got !!!!"

    all_ip = scan_save_db.objects.filter(project_id=project_id)
    all_ip_vul = scan_save_db.objects.filter(project_id=project_id, scan_ip=scan_ip)

    return render(request, 'web_dashboard.html',
                  {'all_data': all_data, 'all_scan_url': all_scan_url, 'all_url_vuln': all_url_vuln,
                   'all_ip': all_ip,
                   'all_ip_vul': all_ip_vul})


def dashboard_network(request):
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
    global new_uri
    new_uri = url
    try:
        driver.get(url, )
    except Exception as e:
        print "Error Got !!!"


def save_cookie(driver):
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

        # chk_url = cookie_db.objects.filter(url=new_uri)
        # for da in chk_url:
        #     print "check url:", da.url
        #     if da.url == new_uri:
        #         chk_url.delete()
        #         print "check url delete"
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
    exclud = request.POST.get("exclude_url", )

    exclude_save = excluded_db(exclude_url=exclud)
    exclude_save.save()

    return render(request, 'webscanner.html', )


def edit_vuln(request):
    # all_vuln = zap_scan_results_db.objects.all()
    if request.method == 'POST':
        vuln_id = request.POST.get("vuln_id", )
        scan_id = request.POST.get("scan_id", )
        name = request.POST.get("name", )
        risk = request.POST.get("risk", )
        url = request.POST.get("url", )
        description = request.POST.get("description", )
        solution = request.POST.get("solution", )
        param = request.POST.get("param", )
        sourceid = request.POST.get("sourceid", )
        attack = request.POST.get("attack", )
        reference = request.POST.get("reference", )
        # vuln_col = request.POST.get("vuln_color", )

        global vul_col

        if risk == 'High':
            vul_col = "important"
        elif risk == 'Medium':
            vul_col = "warning"
        elif risk == 'Low':
            vul_col = "info"
        else:
            vul_col = "info"

        zap_scan_results_db.objects.filter(vuln_id=vuln_id).update(name=name, vuln_color=vul_col, risk=risk,
                                                                   url=url,
                                                                   description=description,
                                                                   solution=solution, param=param,
                                                                   sourceid=sourceid, attack=attack,
                                                                   reference=reference)

        # messages.success(request, "Vulnerability Edited")
        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/webscanners/vuln_dat/?vuln_id=%s" % vuln_id)

        # return HttpResponseRedirect(
        #     reversed('vuln_details.html')
        # )
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    edit_vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'edit_vuln_data.html', {'edit_vul_dat': edit_vul_dat})


def del_vuln(request):
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
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
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'vuln_data.html', {'vul_dat': vul_dat})


def edit_vuln_check(request):
    if request.method == 'GET':
        id_vul = request.GET['vuln_id']

    else:
        id_vul = ''

    edit_vul_dat = zap_scan_results_db.objects.filter(vuln_id=id_vul).order_by('vuln_id')

    return render(request, 'edit_vuln_data.html', {'edit_vul_dat': edit_vul_dat})


def add_vuln(request):
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
        scanners = request.GET['scanner']

    else:
        scan_id = ''
        scanners = ''

    if request.method == 'POST':
        vuln_id = uuid.uuid4()
        scan_id = request.POST.get("scan_id", )
        scanners = request.POST.get("scanners", )
        vuln_name = request.POST.get("vuln_name", )
        risk = request.POST.get("risk", )
        url = request.POST.get("url", )
        param = request.POST.get("param", )
        sourceid = request.POST.get("sourceid", )
        attack = request.POST.get("attack", )
        ref = request.POST.get("ref", )
        description = request.POST.get("description", )
        solution = request.POST.get("solution", )

        req_header = request.POST.get("req_header", )
        res_header = request.POST.get("res_header", )
        vuln_col = request.POST.get("vuln_color", )

        print scanners

        if scanners == 'zap':
            save_vuln = zap_scan_results_db(scan_id=scan_id, vuln_color=vuln_col, risk=risk, url=url, param=param,
                                            sourceid=sourceid,
                                            attack=attack, vuln_id=vuln_id, name=vuln_name,
                                            description=description,
                                            reference=ref,
                                            solution=solution,
                                            requestHeader=req_header, responseHeader=res_header)
            save_vuln.save()

            messages.success(request, "Vulnerability Added")
            zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_id).values('name', 'risk',
                                                                                     'vuln_color').distinct()
            total_vul = len(zap_all_vul)
            total_high = len(zap_all_vul.filter(risk="High"))
            total_medium = len(zap_all_vul.filter(risk="Medium"))
            total_low = len(zap_all_vul.filter(risk="Low"))

            zap_scans_db.objects.filter(scan_scanid=scan_id).update(total_vul=total_vul, high_vul=total_high,
                                                                    medium_vul=total_medium, low_vul=total_low)
            return HttpResponseRedirect("/webscanners/web_vuln_list/?scan_id=%s" % scan_id)

        elif scanners == 'burp':
            save_burp_vuln = burp_scan_result_db(scan_id=scan_id, severity_color=vuln_col, severity=risk,
                                                 host=url, location=param,
                                                 vuln_id=vuln_id, name=vuln_name,
                                                 issueBackground=description,
                                                 references=ref,
                                                 remediationBackground=solution,
                                                 scan_request=req_header, scan_response=res_header)
            save_burp_vuln.save()

            burp_all_vul = burp_scan_result_db.objects.filter(scan_id=scan_id)

            total_vul = len(burp_all_vul)
            total_high = len(burp_all_vul.filter(severity="High"))
            total_medium = len(burp_all_vul.filter(severity="Medium"))
            total_low = len(burp_all_vul.filter(severity="Low"))

            burp_scan_db.objects.filter(scan_id=scan_id).update(total_vul=total_vul, high_vul=total_high,
                                                                medium_vul=total_medium, low_vul=total_low)

            return HttpResponseRedirect("/webscanners/burp_vuln_list?scan_id=%s" % scan_id)

    return render(request, 'add_vuln.html', {'scan_id': scan_id, 'scanners': scanners})


def create_vuln(request):
    return render(request, 'add_vuln.html')


def scan_pdf_gen(request):
    all_scan = zap_scans_db.objects.all()

    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")
        vuln_scan = zap_scan_results_db.objects.filter(scan_id=scan_id)
        zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_id).values('name', 'risk', 'vuln_color',
                                                                                 'scan_id', ).distinct()

        return render_to_pdf_response(request, template=str('pdf_generate.html'), download_filename=None,
                                      content_type='application/pdf',
                                      context={'all_scan': all_scan, 'vuln_scan': vuln_scan, 'scan_url': scan_url,
                                               'zap_all_vul': zap_all_vul})


def burp_setting(request):
    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        burp_path = data['burp_path']
        burp_port = data['burp_port']

    if request.method == 'POST':
        burpath = request.POST.get("burpath", )
        burport = request.POST.get("burport", )
    else:
        burpath = burp_path
        burport = burp_port

    with open(api_key_path, 'r+') as f:
        data = json.load(f)
        data['burp_path'] = burpath
        data['burp_port'] = burport
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()

    return render(request, 'burp_setting_form.html')


def burp_scan_launch(request):
    global vuln_id, burp_status

    if request.POST.get("url", ):
        target_url = request.POST.get('url', )
        project_id = request.POST.get('project_id', )
        scan_id = uuid.uuid4()
        date_time = datetime.datetime.now()

        scan_dump = burp_scan_db(scan_id=scan_id, project_id=project_id, url=target_url, date_time=date_time)
        scan_dump.save()
        try:
            do_scan = burp_scans(project_id, target_url, scan_id)
            do_scan.scan_lauch(project_id, target_url, scan_id)
        except Exception as e:
            print e

    return render(request, 'scan_list.html')


def burp_scan_list(request):
    all_burp_scan = burp_scan_db.objects.all()

    return render(request, 'burp_scan_list.html', {'all_burp_scan': all_burp_scan})


def burp_list_vuln(request):
    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    burp_all_vul = burp_scan_result_db.objects.filter(scan_id=scan_id).values('name', 'severity', 'severity_color',
                                                                              'scan_id').distinct()

    return render(request, 'burp_list_vuln.html', {'burp_all_vul': burp_all_vul, 'scan_id': scan_id})


requestz = ""


def burp_vuln_data(request):
    if request.method == 'GET':
        # scan_id = request.GET['scan_id']
        vuln_id = request.GET['vuln_id']
    else:
        # scan_id = None
        vuln_id = None

    print vuln_id

    vuln_data = burp_scan_result_db.objects.filter(vuln_id=vuln_id)

    return render(request, 'burp_vuln_data.html', {'vuln_data': vuln_data, })


def burp_vuln_out(request):
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
            '/webscanners/burp_vuln_out/?scan_id=%s&scan_name=%s' % (scan_id, vuln_name))

    vuln_data = burp_scan_result_db.objects.filter(scan_id=scan_id, name=name, false_positive='No')
    false_data = burp_scan_result_db.objects.filter(scan_id=scan_id,
                                                    name=name,
                                                    false_positive='Yes')

    return render(request, 'burp_vuln_out.html', {'vuln_data': vuln_data, 'false_data': false_data})


def del_burp_scan(request):
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")

        item = burp_scan_db.objects.filter(scan_id=scan_id, url=scan_url)
        item.delete()
        item_results = burp_scan_result_db.objects.filter(scan_id=scan_id)
        item_results.delete()
        messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/webscanners/burp_scan_list/')


def edit_burp_vuln(request):
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

        burp_scan_result_db.objects.filter(vuln_id=vuln_id).update(name=name,
                                                                   severity_color=vul_col, severity=severity,
                                                                   host=host, path=path, location=location,
                                                                   issueDetail=issuedetail,
                                                                   issueBackground=description,
                                                                   remediationBackground=solution,
                                                                   vulnerabilityClassifications=vulnerabilityClassifications, )

        # messages.success(request, "Vulnerability Edited")
        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/webscanners/burp_vuln_data/?vuln_id=%s" % vuln_id)

    return render(request, 'edit_burp_vuln.html', {'edit_vul_dat': edit_vul_dat})


def xml_upload(request):
    all_project = project_db.objects.all()

    if request.method == "POST":
        project_id = request.POST.get("project_id")
        scanner = request.POST.get("scanner")
        xml_file = request.FILES['xmlfile']
        scan_url = request.POST.get("scan_url")
        scan_id = uuid.uuid4()
        scan_status = "100"
        if scanner == "zap_scan":
            date_time = datetime.datetime.now()
            scan_dump = zap_scans_db(scan_url=scan_url, scan_scanid=scan_id, date_time=date_time,
                                     project_id=project_id,
                                     vul_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            zap_xml_parser.xml_parser(project_id=project_id, scan_id=scan_id, root=root_xml)
            return HttpResponseRedirect("/webscanners/scans_list/")
        elif scanner == "burp_scan":

            date_time = datetime.datetime.now()
            scan_dump = burp_scan_db(url=scan_url, scan_id=scan_id, date_time=date_time, project_id=project_id,
                                     scan_status=scan_status)
            scan_dump.save()
            # Burp scan XML parser
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            do_xml_data = burp_scans(project_id, target_url, scan_id)
            do_xml_data.burp_scan_data(root_xml)
            print "Save scan Data"
            return HttpResponseRedirect("/webscanners/burp_scan_list")

        elif scanner == "arachni":
            print scanner
            print xml_file
            print scan_url
            date_time = datetime.datetime.now()
            scan_dump = arachni_scan_db(url=scan_url, scan_id=scan_id, date_time=date_time, project_id=project_id,
                                        scan_status=scan_status)
            scan_dump.save()
            tree = ET.parse(xml_file)
            root_xml = tree.getroot()
            arachni_xml_parser.xml_parser(project_id=project_id, scan_id=scan_id, root=root_xml)
            print "Save scan Data"
            return HttpResponseRedirect("/webscanners/arachni_scan_list")

    return render(request, 'upload_xml.html', {'all_project': all_project})


def add_cookies(request):

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
            data_dump = cookie_db(url=target_url, cookie=target_cookies)
            data_dump.save()
            return HttpResponseRedirect("/webscanners/")

    return render(request, 'cookie_add.html')


def arachni_list_vuln(request):

    if request.method == 'GET':
        scan_id = request.GET['scan_id']
    else:
        scan_id = None

    arachni_all_vul = arachni_scan_result_db.objects.filter(scan_id=scan_id).values('name', 'severity', 'vuln_color',
                                                                              'scan_id').distinct()

    return render(request, 'arachni_list_vuln.html', {'arachni_all_vul': arachni_all_vul, 'scan_id': scan_id})


def arachni_scan_list(request):
    all_arachni_scan = arachni_scan_db.objects.all()

    return render(request, 'arachni_scan_list.html', {'all_arachni_scan': all_arachni_scan})


def arachni_vuln_data(request):
    if request.method == 'GET':
        # scan_id = request.GET['scan_id']
        vuln_id = request.GET['vuln_id']
    else:
        # scan_id = None
        vuln_id = None

    vuln_data = arachni_scan_result_db.objects.filter(vuln_id=vuln_id)

    return render(request, 'arachni_vuln_data.html', {'vuln_data': vuln_data, })


def arachni_vuln_out(request):
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

    vuln_data = arachni_scan_result_db.objects.filter(scan_id=scan_id, name=name, false_positive='No')
    false_data = arachni_scan_result_db.objects.filter(scan_id=scan_id,
                                                    name=name,
                                                    false_positive='Yes')

    return render(request, 'arachni_vuln_out.html', {'vuln_data': vuln_data, 'false_data': false_data})


def del_arachni_scan(request):
    if request.method == 'POST':
        scan_id = request.POST.get("scan_id")
        scan_url = request.POST.get("scan_url")

        item = arachni_scan_db.objects.filter(scan_id=scan_id, url=scan_url)
        item.delete()
        item_results = arachni_scan_result_db.objects.filter(scan_id=scan_id)
        item_results.delete()
        messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/webscanners/arachni_scan_list/')


def edit_arachni_vuln(request):
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

        burp_scan_result_db.objects.filter(vuln_id=vuln_id).update(name=name,
                                                                   severity_color=vul_col, severity=severity,
                                                                   host=host, path=path, location=location,
                                                                   issueDetail=issuedetail,
                                                                   issueBackground=description,
                                                                   remediationBackground=solution,
                                                                   vulnerabilityClassifications=vulnerabilityClassifications, )

        # messages.success(request, "Vulnerability Edited")
        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/webscanners/burp_vuln_data/?vuln_id=%s" % vuln_id)

    return render(request, 'edit_burp_vuln.html', {'edit_vul_dat': edit_vul_dat})


def arachni_del_vuln(request):
    if request.method == 'POST':
        vuln_id = request.POST.get("del_vuln", )
        un_scanid = request.POST.get("scan_id", )
        delete_vuln = arachni_scan_result_db.objects.filter(vuln_id=vuln_id)
        delete_vuln.delete()
        arachni_all_vul = arachni_scan_result_db.objects.filter(scan_id=un_scanid).values('name', 'severity',
                                                                                   'vuln_color').distinct()
        total_vul = len(arachni_all_vul)
        total_high = len(arachni_all_vul.filter(severity="high"))
        total_medium = len(arachni_all_vul.filter(severity="medium"))
        total_low = len(arachni_all_vul.filter(severity="low"))

        arachni_scan_db.objects.filter(scan_id=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                                  medium_vul=total_medium, low_vul=total_low)
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/webscanners/arachni_list_vuln?scan_id=%s" % un_scanid)