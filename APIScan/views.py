# -*- coding: utf-8 -*-
#                   _
#    /\            | |
#   /  \   _ __ ___| |__   ___ _ __ _   _
#  / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
# / ____ \| | | (__| | | |  __/ |  | |_| |
#/_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                    __/ |
#                                   |___/
# Copyright (C) 2017-2018 ArcherySec
# This file is part of ArcherySec Project.

from __future__ import unicode_literals

from django.shortcuts import render, HttpResponseRedirect
import uuid
from projects.models import project_db
from APIScan.models import APIScan_db, api_token_db, APIScan_url_db
import requests
import ast

from webscanners.models import zap_scan_results_db, zap_scans_db, zap_spider_db, zap_spider_results, cookie_db, \
    excluded_db
from django.db.models import Q
import os
import json
from zapv2 import ZAPv2
import time
# from scanners import zapscanner
from django.http import HttpResponseRedirect
import uuid
from django.core import signing
from projects.models import project_db
import datetime

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
api_token = ""
new_scan = None
scan_id = None


def add_api_scan(request):
    new_scan = request.POST.get("new_scan")
    scan_id = request.POST.get("scan_id")
    auth_url = request.POST.get("auth_url")
    if new_scan == 'Yes':
        new_scan = request.POST.get("new_scan")
        if new_scan == 'Yes':
            project_id = request.POST.get("project_id")
            scan_target = request.POST.get("scan_target")
            req_header = request.POST.get("req_header")
            req_body = request.POST.get("req_body")
            method = request.POST.get("method")
            auth_url = request.POST.get("auth_url")
            scan_id = uuid.uuid4()
            auth_header = request.POST.get("auth_header")

            dump_data = APIScan_db(project_id=project_id, scan_url=scan_target, scan_id=scan_id, req_header=req_header,
                                   req_body=req_body, method=method, auth_url=auth_url, auth_token_key=auth_header)
            dump_data.save()
            return HttpResponseRedirect('/scanapi/')
        else:
            return HttpResponseRedirect('/scanapi/')

    elif scan_id is not None:
        project_id = request.POST.get("project_id")
        scan_target = request.POST.get("scan_target")
        req_header = request.POST.get("req_header")
        req_body = request.POST.get("req_body")
        method = request.POST.get("method")
        auth_url = request.POST.get("auth_url")
        auth_header = request.POST.get("auth_header")
        extra_val_in_auth = request.POST.get("extra_auth_value")
        dump_data = APIScan_url_db(project_id=project_id, scan_url=scan_target, scan_id=scan_id, req_header=req_header,
                                   extra_vaule_auth=extra_val_in_auth,
                                   req_body=req_body, method=method, auth_url=auth_url, auth_token_key=auth_header)
        dump_data.save()
        return HttpResponseRedirect('/scanapi/scanapi/?scan_id=%s' % scan_id)

    all_scans_db = project_db.objects.all()

    return render(request, 'addapiscan.html', {'all_scans_db': all_scans_db})


def add_scan(request):
    global new_scan, scan_id
    new_scan = request.GET['new_scan']
    # scan_id = request.GET['scan_id']
    scan_id = request.GET['scan_id']

    all_scans_db = project_db.objects.all()

    return render(request, 'addapiscan.html', {'all_scans_db': all_scans_db, 'new_scan': new_scan,
                                               'scan_id': scan_id})


def api__scans(request):
    all_api_scans = APIScan_db.objects.all()

    return render(request, 'api_scans.html', {'all_api_scans': all_api_scans})


def list_api_scan(request):
    if request.method == 'GET':
        api_scan_id = request.GET['scan_id']
    else:
        api_scan_id = ''

    all_api_scan = APIScan_url_db.objects.filter(scan_id=api_scan_id, auth_url='Yes')
    all_api_url_scan = APIScan_url_db.objects.filter(scan_id=api_scan_id, auth_url='No')
    all_api_key = api_token_db.objects.all()

    return render(request, 'api_scan_list.html',
                  {'all_api_scan': all_api_scan, 'all_api_key': all_api_key, 'all_api_url_scan': all_api_url_scan,
                   'api_scan_id': api_scan_id})


def del_api_scan(request):
    if request.POST.get("del_scan"):
        del_scan = request.POST.get("del_scan")
        scan_id = request.POST.get("scan_id")
        scan_uuid = request.POST.get("scan_uuid")
        auth_url = request.POST.get("auth_url")
        if del_scan == 'Yes':
            scan_url = request.POST.get("scan_url")
            if auth_url == 'Yes':
                url_scan = APIScan_url_db.objects.filter(id=scan_id, scan_url=scan_url, auth_url='Yes')
                url_scan.delete()
            else:
                url_del = APIScan_url_db.objects.filter(id=scan_id, scan_url=scan_url, auth_url='No')
                url_del.delete()
    return HttpResponseRedirect('/scanapi/scanapi/?scan_id=%s' % scan_uuid)


def del_scans(request):
    if request.POST.get("scan_id"):
        scan_id = request.POST.get("scan_id")
        scan_uuid = request.POST.get("scan_uuid")
        item = APIScan_db.objects.filter(scan_id=scan_uuid, id=scan_id)
        item.delete()
        return HttpResponseRedirect('/scanapi/api_scans/')
    else:
        return HttpResponseRedirect('/scanapi/api_scans/')


def edit_scan(request):
    if request.method == 'GET':
        api_scan_id = request.GET['scan_id']
        scan_uuid = request.GET['scan_uuid']
        new_scan = request.GET['new_scan']
        scan_url = request.GET['scan_url']
    else:
        api_scan_id = None
        new_scan = None
        scan_url = None
        scan_uuid = None

    if new_scan == 'Yes':
        all_scan = APIScan_db.objects.filter(id=api_scan_id, scan_id=scan_uuid, scan_url=scan_url)
    else:
        all_scan = APIScan_url_db.objects.filter(id=api_scan_id, scan_id=scan_uuid, scan_url=scan_url)

    if request.POST.get("new_scan"):
        new_scans = request.POST.get("new_scan")
        print new_scans
        if new_scans == 'Yes':
            scan_uuid = request.POST.get("scan_uuid")
            new_scan_url = request.POST.get("scan_url")
            req_header = request.POST.get("req_header")
            req_body = request.POST.get("req_body")
            method = request.POST.get("method")
            auth_header = request.POST.get("auth_header")
            APIScan_db.objects.filter(scan_id=scan_uuid).update(scan_url=new_scan_url,
                                                                req_header=req_header,
                                                                req_body=req_body,
                                                                method=method,
                                                                auth_token_key=auth_header)

            return HttpResponseRedirect('/scanapi/')
        else:
            scan_id = request.POST.get("scan_id")
            scan_uuid = request.POST.get("scan_uuid")
            new_scan_url = request.POST.get("scan_url")
            scan_url = request.POST.get("old_url")
            print new_scan_url
            print scan_url
            req_header = request.POST.get("req_header")
            req_body = request.POST.get("req_body")
            method = request.POST.get("method")
            auth_header = request.POST.get("auth_header")
            APIScan_url_db.objects.filter(id=scan_id, scan_id=scan_uuid, scan_url=scan_url).update(
                scan_url=new_scan_url,
                req_header=req_header,
                req_body=req_body,
                method=method,
                auth_token_key=auth_header)
            return HttpResponseRedirect('/scanapi/scanapi/?scan_id=%s' % scan_uuid)

    return render(request, 'edit_scan.html', {'all_scan': all_scan, 'new_scan': new_scan})


def authenticate(request):
    global keyl
    if request.POST.get("scan_url"):
        auth_val = request.POST.get("auth_val")
        if auth_val == 'Yes':
            scan_url = request.POST.get("scan_url")
            req_header = ast.literal_eval(request.POST.get("req_header"))
            req_body = request.POST.get("req_body")
            method = request.POST.get("method")
            project_id = request.POST.get("project_id")
            scan_id = request.POST.get("scan_id")
            auth_token_key = request.POST.get("auth_token_key")
            extra_val_in_auth = request.POST.get("extra_auth_value")

            print scan_url
            p = json.loads(json.dumps(req_header))
            print p
            for key, value in p.iteritems():
                print key, value

            r = requests.post(scan_url, headers=req_header, data=req_body)

            data = json.loads(r.text)
            for key, value in data.viewitems():
                keyl = data[key]
                api_token = extra_val_in_auth + " " + keyl
                print api_token

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
                            proxies={'http': 'http://127.0.0.1' + ':' + zap_port,
                                     'https': 'http://127.0.0.1' + ':' + zap_port})
                try:
                    zap_scanner = zapscanner.start_zap()
                    print "Status of zap scanner:", zap_scanner

                except Exception as e:
                    print e
                    return HttpResponseRedirect("/webscanners/scans_list/")

                time.sleep(10)

                """ Excluding URL from scanner """

                remove_auth = zap.replacer.remove_rule(scan_url)
                print "Remove Auth :", remove_auth
                print "Auth token Key :", auth_token_key
                auth_token_add = zap.replacer.add_rule(apikey=apikey, description=scan_url, enabled="true",
                                                       matchtype='REQ_HEADER', matchregex="false",
                                                       replacement=api_token,
                                                       matchstring=auth_token_key, initiators="")

                print "Auth Added :", auth_token_add

                p = json.loads(json.dumps(req_header))
                print p
                for key, value in p.iteritems():
                    print key, value
                # remove_header = zap.replacer.remove_rule(target_url)
                # print "Remove extra value header :", remove_header
                header_add = zap.replacer.add_rule(apikey=apikey, description=scan_url, enabled="true",
                                                   matchtype='REQ_HEADER', matchregex="false",
                                                   replacement=value,
                                                   matchstring=key, initiators="")
                print "Cookies Added :", header_add

                api_token_db.objects.filter(scan_url=scan_url).update(api_token=api_token)

                return HttpResponseRedirect('/scanapi/')

    else:

        return HttpResponseRedirect('/scanapi/')


def auth_token_list(request):
    return render(request, 'api_scan_list.html')


def url_api_scan(request):
    if request.POST.get("auth_val"):
        auth_val = request.POST.get("auth_val")
        print auth_val
        if auth_val == 'No':
            target_url = request.POST.get("scan_url")
            req_header = ast.literal_eval(request.POST.get("req_header"))
            req_body = request.POST.get("req_body")
            method = request.POST.get("method")
            project_id = request.POST.get("project_id")
            scan_id = request.POST.get("scan_id")
            auth_token_key = request.POST.get("auth_token_key")
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
                        proxies={'http': 'http://127.0.0.1' + ':' + zap_port,
                                 'https': 'http://127.0.0.1' + ':' + zap_port})

            print target_url

            """
                ***Starting ZAP Scanner***
            """
            try:
                zap_scanner = zapscanner.start_zap()
                print "Status of zap scanner:", zap_scanner

            except Exception as e:
                print e
                return HttpResponseRedirect("/webscanners/scans_list/")

            """
                *****End zap scanner****
            """

            time.sleep(10)

            """ Excluding URL from scanner """

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

            print 'Spider Completed------'
            print 'Target :', target_url
            global spider_alert
            spider_alert = "Spider Completed"

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

            # zap_scanner = zapscanner.stop_zap()
            print "Status of zap scanner:", zap_scanner

            return HttpResponseRedirect('/scanapi/')

    return render(request, 'api_scan_list.html')
