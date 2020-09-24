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

""" Author: Anand Tiwari """

from __future__ import unicode_literals
import json
from vFeed.lib.core.methods import *
from django.shortcuts import render, HttpResponse, HttpResponseRedirect
from notifications.signals import notify

cve_summary = ''
cve_url = ''
cve_id = ''
cve_modified = ''
zcve_published = ''
cwe_id = ''
cwe_title = ''
cwe_url = ''
cvss_accessComplexity = ''
cvss_accessVector = ''
cvss_authentication = ''
cvss_availability = ''
cvss_base = ''
cvss_confidentiality = ''
cvss_exploitability = ''
cvss_impact = ''
cvss_integrity = ''
cvss_vector = ''
cvss2_accessComplexity = ''
cvss2_accessVector = ''
ubuntu_id = ''
ubuntu_url = ''
nessus_json_data = ''
nessus_family = ''
nessus_file = ''
nessus_id = ''
nessus_name = ''
ubuntu_json_data = ''
oval_json_data = ''
oval_class = ''
oval_id = ''
oval_title = ''
oval_url = ''
metasploit_json_data = ''
metasploit_file = ''
metasploit_id = ''
metasploit_title = ''
snort_category = ''
snort_id = ''
snort_signature = ''
cvss2_authentication = ''
cvss2_availability = ''
cvss2_base = ''
cvss2_confidentiality = ''
cvss2_exploitability = ''
cvss2_impact = ''
cvss2_integrity = ''
cvss2_vector = ''
cve_published = ''


def cve_info(request):
    user = request.user
    global cve_summary, cve_url, cve_id, cve_modified, cve_published, \
        cwe_id, cwe_title, cwe_url, cvss_accessComplexity, \
        cvss_accessVector, cvss_authentication, cvss_availability, \
        cvss_base, cvss_confidentiality, cvss_exploitability, \
        cvss_impact, cvss_integrity, cvss_vector, \
        cvss2_accessComplexity, cvss2_accessVector, ubuntu_id, \
        ubuntu_url, nessus_json_data, nessus_family, \
        nessus_file, nessus_id, nessus_name, ubuntu_json_data, \
        oval_json_data, oval_class, oval_id, oval_title, oval_url, \
        metasploit_json_data, metasploit_file, metasploit_id, \
        metasploit_title, snort_category, snort_id, snort_signature, cve_dat, cvss2_authentication, cvss2_availability, cvss2_base, cvss2_confidentiality, cvss2_exploitability, cvss2_impact, cvss2_integrity, cvss2_vector
    if request.GET['cve']:
        cve_dat = request.GET['cve']
    else:
        cve_dat = ''
    cve = cve_dat.replace(" ", "")

    try:
        print(CveInfo(str(cve)).get_cve())
    except Exception:
        print("")
        notify.send(user, recipient=user, verb='vFeed database not found')
        return HttpResponseRedirect('/')

    info = CveInfo(str(cve)).get_cve()
    cwe = CveInfo(cve).get_cwe()
    json_data = json.loads(info)
    try:
        for j in json_data:
            cve_url = j['url']
            cve_summary = j['summary']
            cve_id = j['id']
            cve_modified = j['modified']
            cve_published = j['published']
    except Exception as e:
        print(e)

    cwe_json_data = json.loads(cwe)
    try:
        for cwe_data in cwe_json_data:
            cwe_id = cwe_data['id']
            cwe_title = cwe_data['title']
            cwe_url = cwe_data['url']
    except Exception as e:
        print(e)

    cvss = CveRisk(cve).get_cvss()
    try:
        cvss_json_data = json.loads(cvss)
    except Exception as e:
        print(e)
    try:
        for cvss_data in cvss_json_data:
            cvss_accessComplexity = cvss_data['accessComplexity']
            cvss_accessVector = cvss_data['accessVector']
            cvss_authentication = cvss_data['authentication']
            cvss_availability = cvss_data['availability']
            cvss_base = cvss_data['base']
            cvss_confidentiality = cvss_data['confidentiality']
            cvss_exploitability = cvss_data['exploitability']
            cvss_impact = cvss_data['impact']
            cvss_integrity = cvss_data['integrity']
            cvss_vector = cvss_data['vector']
    except Exception as e:
        print(e)

    severity = CveRisk(cve).get_severity()
    try:
        severity_json_data = json.loads(severity)
    except Exception as e:
        print(e)
    # print severity
    severity_id = {}
    severity_title = {}
    try:
        for severity in severity_json_data:
            if severity["topAlert"] == False:
                severity_id = ''
                severity_title = ''
            else:

                for app in severity["topAlert"]:
                    severity_id[app['id']] = app['title']
                    severity_title[app['title']] = 'test'
            for cvss2_data in severity['cvss2']:
                cvss2_accessComplexity = cvss2_data['accessComplexity']
                cvss2_accessVector = cvss2_data['accessVector']
                cvss2_authentication = cvss2_data['authentication']
                cvss2_availability = cvss2_data['availability']
                cvss2_base = cvss2_data['base']
                cvss2_confidentiality = cvss2_data['confidentiality']
                cvss2_exploitability = cvss2_data['exploitability']
                cvss2_impact = cvss2_data['impact']
                cvss2_integrity = cvss2_data['integrity']
                cvss2_vector = cvss2_data['vector']
    except Exception as e:
        print(e)

    ubuntu = CvePatches(cve).get_ubuntu()
    # print(ubuntu)
    try:
        ubuntu_json_data = json.loads(ubuntu)
    except Exception as e:
        print(e)
    if ubuntu == None:
        ubuntu_id = ''
        ubuntu_url = ''
    else:
        try:
            for ubuntu in ubuntu_json_data:
                ubuntu_id = ubuntu['id']
                ubuntu_url = ubuntu['url']
        except Exception as e:
            print(e)

    nessus = CveScanners(cve).get_nessus()
    # print(nessus)
    try:
        nessus_json_data = json.loads(nessus)
    except Exception as e:
        print(e)

    if nessus == None:
        pass
    else:
        try:
            nessus_family = {}
            nessus_file = {}
            nessus_id = {}
            nessus_name = {}
            for nessus in nessus_json_data:
                nessus_family[nessus['family']] = 'family'
                nessus_file[nessus['file']] = 'file'
                nessus_id[nessus['id']] = 'id'
                nessus_name[nessus['name']] = 'name'
        except Exception as e:
            print(e)

    oval = CveScanners(cve).get_oval()
    # print(oval)
    try:
        oval_json_data = json.loads(oval)
    except Exception as e:
        print(e)

    if oval == 'null':
        pass
    else:
        try:
            oval_class = {}
            oval_id = {}
            oval_title = {}
            oval_url = {}
            for oval_data in oval_json_data:
                oval_class[oval_data['class']] = 'class'
                oval_id[oval_data['id']] = 'id'
                oval_title[oval_data['title']] = 'title'
                oval_url[oval_data['url']] = 'url'
        except Exception as e:
            print(e)

    metasploit = CveExploit(cve).get_msf()

    try:
        metasploit_json_data = json.loads(metasploit)
    except Exception as e:
        print(e)

    if metasploit == 'null':
        pass
    else:
        try:
            for metasploit_data in metasploit_json_data:
                metasploit_file = metasploit_data['file']
                metasploit_id = metasploit_data['id']
                metasploit_title = metasploit_data['title']
        except Exception as e:
            print(e)

    snort = CveRules(cve).get_snort()
    # print(snort)

    if snort == 'null':
        pass
    else:
        snort_json_data = json.loads(snort)
        # print snort_json_data
        snort_category = {}
        snort_id = {}
        snort_signature = {}
        for snort_data in snort_json_data:
            snort_category[snort_data['category']] = 'category'
            snort_id[snort_data['id']] = 'id'
            snort_signature[snort_data['signature']] = 'signature'

    # print("Total of Nessus scripts found is:", len(json.loads(nessus)))

    return render(request,
                  'vfeed/cve_info.html',
                  {'cve_url': cve_url,
                   'cve_summary': cve_summary,
                   'cve_id': cve_id,
                   'cve_modified': cve_modified,
                   'cve_published': cve_published,
                   'cwe_id': cwe_id,
                   'cwe_title': cwe_title,
                   'cwe_url': cwe_url,
                   'cvss_accessComplexity': cvss_accessComplexity,
                   'cvss_accessVector': cvss_accessVector,
                   'cvss_authentication': cvss_authentication,
                   'cvss_availability': cvss_availability,
                   'cvss_base': cvss_base,
                   'cvss_confidentiality': cvss_confidentiality,
                   'cvss_exploitability': cvss_exploitability,
                   'cvss_impact': cvss_impact,
                   'cvss_integrity': cvss_integrity,
                   'cvss_vector': cvss_vector,

                   'cvss2_accessComplexity': cvss2_accessComplexity,
                   'cvss2_accessVector': cvss2_accessVector,
                   'cvss2_authentication': cvss2_authentication,
                   'cvss2_availability': cvss2_availability,
                   'cvss2_base': cvss2_base,
                   'cvss2_confidentiality': cvss2_confidentiality,
                   'cvss2_exploitability': cvss2_exploitability,
                   'cvss2_impact': cvss2_impact,
                   'cvss2_integrity': cvss2_integrity,
                   'cvss2_vector': cvss2_vector,
                   'severity_id': severity_id,
                   'severity_title': severity_title,
                   'ubuntu_id': ubuntu_id,
                   'ubuntu_url': ubuntu_url,

                   'nessus_family': nessus_family,
                   'nessus_file': nessus_file,
                   'nessus_id': nessus_id,
                   'nessus_name': nessus_name,

                   'oval_class': oval_class,
                   'oval_id': oval_id,
                   'oval_title': oval_title,
                   'oval_url': oval_url,

                   'metasploit_file': metasploit_file,
                   'metasploit_id': metasploit_id,
                   'metasploit_title': metasploit_title,

                   'snort_category': snort_category,
                   'snort_id': snort_id,
                   'snort_signature': snort_signature

                   }
                  )
