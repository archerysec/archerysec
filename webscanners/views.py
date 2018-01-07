from __future__ import unicode_literals

from django.shortcuts import render, render_to_response, HttpResponse
from .models import zap_scan_results_db, zap_scans_db, zap_spider_db, zap_spider_results, cookie_db, excluded_db
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

api_key_path = os.getcwd() + '/' + 'apidata.json'

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

# Login View
@public
@csrf_protect
def login(request):
    c = {}
    c.update(request)
    return render(request, "login.html", c)


@public
def auth_view(request):
    username = request.POST.get('username', '')
    password = request.POST.get('password', '')
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


def loggedin(request):
    return render(request, 'webscanner.html')


def invalid_login():
    return render_to_response('invalid_login.html')


def index(request):
    try:
        with open(api_key_path, 'r+') as f:
            data = json.load(f)
            lod_apikey = data['zap_api_key']
            apikey = signing.loads(lod_apikey)
            zapath = data['zap_path']
            zap_port = data['zap_port']
    except Exception as e:
        print e

    zap = ZAPv2(apikey=apikey,
                proxies={'http': 'http://127.0.0.1' + ':' + zap_port, 'https': 'http://127.0.0.1' + ':' + zap_port})

    all_urls = zap_spider_db.objects.all()
    all_scans = zap_scans_db.objects.all()
    all_spider_results = zap_spider_results.objects.all()
    all_excluded_url = excluded_db.objects.all()
    all_cookies = cookie_db.objects.all()

    all_scans_db = project_db.objects.all()

    if request.POST.get("url"):
        global target_url
        target_url = request.POST.get('url')
        project_id = request.POST.get('project_id')
        print target_url
        try:
            abc = zapscanner.start_zap()
            print abc
            messages.success(request, "ZAP Started")
        except Exception as e:
            messages.error(request, "Please Setup ZAP configuration in ZAP setting page")
            print e
            return HttpResponseRedirect("/webscanners/scans_list/")

        messages.success(request, "ZAP Started")
        messages.add_message(request, messages.SUCCESS, 'ZAP Started')

        time.sleep(10)

        all_excluded = excluded_db.objects.filter(Q(exclude_url__icontains=target_url))

        for data in all_excluded:
            global excluded_url
            excluded_url = data.exclude_url

        print "Exclude url ", excluded_url
        url_exclude = zap.spider.exclude_from_scan(regex=excluded_url)

        print "URL Excluded:", url_exclude

        all_cookie = cookie_db.objects.filter(url=target_url)
        for da in all_cookie:
            global cookies
            cookies = da.cookie
        remove_cookie = zap.replacer.remove_rule(target_url)
        print "Remove Cookie :", remove_cookie
        cookie_add = zap.replacer.add_rule(apikey=apikey, description=target_url, enabled="true",
                                           matchtype='REQ_HEADER', matchregex="false", replacement=cookies,
                                           matchstring="Cookie", initiators="")

        print "Cookies Added :", cookie_add
        zap.ajaxSpider.scan(target_url)
        scanid = zap.spider.scan(target_url)

        save_all = zap_spider_db(spider_url=target_url, spider_scanid=scanid)
        save_all.save()
        try:
            while (int(zap.spider.status(scanid)) < 100):
                # print 'Spider progress %:' + zap.spider.status(scanid)
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
        total_spider = len(spider_res_out)
        save_spider_results = zap_spider_results(spider_id=(scanid), spider_urls=(data_out))
        save_spider_results.save()
        del_temp = zap_spider_db.objects.filter(spider_scanid__icontains=scanid).order_by('spider_scanid')
        del_temp.delete()
        save_all = zap_spider_db(spider_url=target_url, spider_scanid=scanid, urls_num=total_spider)
        save_all.save()

        print 'Spider Completed------'
        print 'Target :', target_url
        global spider_alert
        spider_alert = "Spider Completed"

        messages.add_message(request, messages.SUCCESS, 'Spider Completed ')

        time.sleep(5)

        print 'Scanning Target %s' % target_url
        scan_scanid = zap.ascan.scan(target_url)
        un_scanid = uuid.uuid4()
        print "updated scanid :", un_scanid
        try:
            save_all_scan = zap_scans_db(project_id=project_id, scan_url=target_url, scan_scanid=un_scanid)
            save_all_scan.save()
        except Exception as e:
            print e
        # zap_scans_db.objects.filter(pk=some_value).update(field1='some value')
        try:
            while (int(zap.ascan.status(scan_scanid)) < 100):
                print 'Scan progress from zap_scan_lauch function  %: ' + zap.ascan.status(scan_scanid)
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
        # print all_vuln

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

            global vul_col

            if risk == 'High':
                vul_col = "important"
            elif risk == 'Medium':
                vul_col = "warning"
            elif risk == 'Low':
                vul_col = "info"

            dump_all = zap_scan_results_db(vuln_id=vuln_id, vuln_color=vul_col, scan_id=un_scanid,
                                           project_id=project_id,
                                           confidence=confidence, wascid=wascid,
                                           cweid=cweid,
                                           risk=risk, reference=reference, url=url, name=name,
                                           solution=solution,
                                           param=param, evidence=evidence, sourceid=sourceid, pluginId=pluginId,
                                           other=other, attack=attack, messageId=messageId, method=method,
                                           alert=alert, id=ids, description=description)
            dump_all.save()

        time.sleep(5)

        zap_all_vul = zap_scan_results_db.objects.filter(scan_id=un_scanid).order_by('scan_id')
        total_vul = len(zap_all_vul)
        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))

        zap_scans_db.objects.filter(scan_scanid=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                                  medium_vul=total_medium, low_vul=total_low)

        spider_alert = "Scan Completed"

        time.sleep(5)

        for msg in zap_all_vul:
            msg_id = msg.messageId
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
            print msg_id
            print res_id

            # vuln_num = zap.core.number_of_alerts(target_url)

    return render(request, 'webscanner.html',
                  {'all_urls': all_urls, 'spider_status': spider_status, 'scans_status': scans_status,
                   'all_scans': all_scans, 'all_spider_results': all_spider_results, 'spider_alert': spider_alert,
                   'all_excluded_url': all_excluded_url, 'all_cookies': all_cookies, 'all_scans_db': all_scans_db})


def scan_list(request):
    all_scans = zap_scans_db.objects.all()

    return render(request, 'scan_list.html', {'all_scans': all_scans})


def vuln_details(request):
    if request.method == 'GET':
        scan_vul = request.GET['scan_id']

    else:
        scan_vul = ''

    zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_vul).order_by('scan_id')

    return render(request, 'vuln_details.html', {'zap_all_vul': zap_all_vul, 'scan_vul': scan_vul})


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

    return render(request, 'setting.html',
                  {'apikey': lod_apikey, 'zapath': zapath, 'zap_port': zap_port, 'lod_ov_user': lod_ov_user,
                   'lod_ov_pass': lod_ov_pass, 'lod_ov_ip': lod_ov_ip})


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
        apikey = request.POST.get("apikey")
        zapath = request.POST.get("zappath")
        port = request.POST.get("port")
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


def scan_table(request):
    all_scans = zap_scans_db.objects.all()

    return render(request, 'scan_table.html', {'all_scans': all_scans})


def del_scan(request):
    all_scans = zap_scans_db.objects.all()
    if request.method == 'GET':
        item_id = request.GET['scan_scanid']

        item = zap_scans_db.objects.filter(scan_scanid=item_id)
        item.delete()
        item_results = zap_scan_results_db.objects.filter(scan_id=item_id)
        item_results.delete()
        messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect('/webscanners/scans_list/')


def dashboard(request):
    return render(request, 'dashboard.html')


def slem(driver, url):
    global new_uri
    new_uri = url
    driver.get(url)


def save_cookie(driver):
    all_cookies = driver.get_cookies()

    f = open('cookies.txt', 'w+')

    for cookie in all_cookies:
        cookie_value = cookie['name'] + '=' + cookie['value'] + ';'
        print cookie_value
        f.write(cookie_value)
    f.close()

    driver.close()

    return HttpResponse(status=201)


def sel_login(request):
    action_vul = request.POST.get("action")
    url_da = request.POST.get("url_login")
    print action_vul
    print url_da
    if action_vul == "open_page":
        global driver
        driver = webdriver.Firefox()
        slem(driver, url_da)
        messages.add_message(request, messages.SUCCESS, 'Opening Website')

    elif action_vul == "save_cookie":
        save_cookie(driver)
        read_f = open('cookies.txt', 'r')

        chk_url = cookie_db.objects.filter(url=new_uri)
        for da in chk_url:
            print "check url:", da.url
            if da.url == new_uri:
                chk_url.delete()

        print "url from cookie : ", new_uri

        for cookie_data in read_f:
            print "Cookies from text :", cookie_data
            cookie_save = cookie_db(url=new_uri, cookie=cookie_data)
            cookie_save.save()

        messages.add_message(request, messages.SUCCESS, 'Cookies stored')

    return HttpResponseRedirect(reversed('webscanner.html'))


def exclude_url(request):
    exclud = request.POST.get("exclude_url")

    exclude_save = excluded_db(exclude_url=exclud)
    exclude_save.save()

    return render(request, 'webscanner.html', )


def edit_vuln(request):
    # all_vuln = zap_scan_results_db.objects.all()
    if request.method == 'POST':
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        print vuln_id
        name = request.POST.get("name")
        risk = request.POST.get("risk")
        url = request.POST.get("url")
        description = request.POST.get("description")
        solution = request.POST.get("solution")
        param = request.POST.get("param")
        sourceid = request.POST.get("sourceid")
        attack = request.POST.get("attack")
        reference = request.POST.get("reference")
        vuln_col = request.POST.get("vuln_color")

        print "edit_vul :", name

        zap_scan_results_db.objects.filter(vuln_id=vuln_id).update(name=name, vuln_color=vuln_col, risk=risk, url=url,
                                                                   description=description,
                                                                   solution=solution, param=param,
                                                                   sourceid=sourceid, attack=attack,
                                                                   reference=reference)

        # messages.success(request, "Vulnerability Edited")
        messages.add_message(request, messages.SUCCESS, 'Vulnerability Edited...')

        return HttpResponseRedirect("/webscanners/zap_vul_details/?scan_id=%s" % scan_id)
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
        vuln_id = request.POST.get("del_vuln")
        un_scanid = request.POST.get("scan_id")
        delete_vuln = zap_scan_results_db.objects.filter(vuln_id=vuln_id)
        delete_vuln.delete()

        zap_all_vul = zap_scan_results_db.objects.filter(scan_id=un_scanid).order_by('scan_id')
        total_vul = len(zap_all_vul)
        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))

        zap_scans_db.objects.filter(scan_scanid=un_scanid).update(total_vul=total_vul, high_vul=total_high,
                                                                  medium_vul=total_medium, low_vul=total_low)
        messages.success(request, "Deleted vulnerability")

        return HttpResponseRedirect("/webscanners/zap_vul_details/?scan_id=%s" % un_scanid)
        # return HttpResponseRedirect(
        #     reversed('vuln_details.html')
        # )


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

    else:
        scan_id = ''

    if request.method == 'POST':
        vuln_id = uuid.uuid4()
        scan_id = request.POST.get("scan_id")
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

        save_vuln = zap_scan_results_db(scan_id=scan_id, vuln_color=vuln_col, risk=risk, url=url, param=param,
                                        sourceid=sourceid,
                                        attack=attack, vuln_id=vuln_id, name=vuln_name, description=description,
                                        reference=ref,
                                        solution=solution,
                                        requestHeader=req_header, responseHeader=res_header)
        save_vuln.save()

        messages.success(request, "Vulnerability Added")
        zap_all_vul = zap_scan_results_db.objects.filter(scan_id=scan_id).order_by('scan_id')
        total_vul = len(zap_all_vul)
        total_high = len(zap_all_vul.filter(risk="High"))
        total_medium = len(zap_all_vul.filter(risk="Medium"))
        total_low = len(zap_all_vul.filter(risk="Low"))

        zap_scans_db.objects.filter(scan_scanid=scan_id).update(total_vul=total_vul, high_vul=total_high,
                                                                medium_vul=total_medium, low_vul=total_low)
        return HttpResponseRedirect("/webscanners/zap_vul_details/?scan_id=%s" % scan_id)

    return render(request, 'add_vuln.html', {'scan_id': scan_id})


def create_vuln(request):
    return render(request, 'add_vuln.html')
