# -*- coding: utf-8 -*-
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
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.shortcuts import render, HttpResponseRedirect
from osintscan.osint_tools.Sublist3r import sublist3r
from projects.models import project_db
from osintscan.models import osint_domain_db, osint_whois_db
import requests
import whois

all_domain = ''
updated_date = ""
status = ""
name = ""
city = ""
expiration_date = ""
zipcode = ""
domain_name = ""
country = ""
whois_server = ""
state = ""
registrar = ""
referral_url = ""
address = ""
name_servers = ""
org = ""
creation_date = ""
emails = ""


def domain_osint(request):
    """
    Calling domain osint activity page.
    :param request:
    :return:
    """
    projects = project_db.objects.all()
    all_domain = osint_domain_db.objects.all()

    return render(request,
                  'domain_search.html',
                  {'projects': projects,
                   'all_domain': all_domain}
                  )


def domain_list(request):
    """

    :param request:
    :return:
    """
    all_domain = osint_domain_db.objects.all().values('domains').distinct()

    return render(request, 'domain_list.html', {'all_domain': all_domain})


def sub_domain_search(request):
    """

    :param request:
    :return:
    """
    mylist = ['http://', 'https://']

    if request.method == 'GET':
        domain = request.GET['domain']
        global all_domain
        all_domain = osint_domain_db.objects.filter(domains=domain)

    if request.method == 'POST':
        domain = request.POST.get('domain')
        project_id = request.POST.get('project_id')

        subdomains = sublist3r.main(domain, False, 'subdomains.txt', ports=None, silent=False,
                                    verbose=False, enable_bruteforce=False, engines=None)
        for sdomain in subdomains:
            print sdomain
            for a in mylist:
                try:
                    # r = requests.get(a + sdomain)
                    print "sasdfasdfasdf", a + sdomain
                    r = requests.head(a + sdomain, allow_redirects=False)
                    print "status code", r.status_code
                    if r.status_code == 200:
                        final_url = a + sdomain
                        print "final url", final_url
                        save_subdoamin = osint_domain_db(domains=domain,
                                                         sub_domains=final_url,
                                                         project_id=project_id)
                        save_subdoamin.save()

                except:
                    print "error as in subdomain"
        return HttpResponseRedirect('/osintscan/domain_list/')

    return render(request, 'sub_domains.html', {'all_domain': all_domain})


def del_sub_domain(request):
    """

    :param request:
    :return:
    """

    if request.method == "POST":
        sub_domain = request.POST.get('sub_domain')
        domain = request.POST.get('domain')

        domain_item = str(sub_domain)
        value = domain_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        print "split_length", split_length
        for i in range(0, split_length):
            sub_domain = value_split.__getitem__(i)
            del_subdomain = osint_domain_db.objects.filter(sub_domains=sub_domain)
            del_subdomain.delete()

        return HttpResponseRedirect('/osintscan/sub_domain_search/?domain=%s' % domain)


def osint_whois(request):
    """

    :param request:
    :return:
    """
    domain_z = ''
    if request.method == "POST":
        domain = request.POST.get('domain')
        project_id = request.POST.get('project_id')
        domain_item = str(domain)
        value = domain_item.replace(" ", "")
        value_split = value.split(',')
        split_length = value_split.__len__()
        for i in range(0, split_length):
            domain_s = value_split.__getitem__(i)
            all_whois_info = osint_whois_db.objects.filter(domain=domain)
            for a in all_whois_info:
                domain_z = a.domain
            if domain_s == domain_z:
                print "Domain Already Existed", domain
                return HttpResponseRedirect('/osintscan/domain_list/')
            else:
                whois_info = whois.whois(domain_s)
                for key, value in whois_info.viewitems():
                    global updated_date
                    if key == 'updated_date':
                        updated_date = value
                    global status
                    if key == 'status':
                        status = value
                    global name
                    if key == 'name':
                        name = value
                    global city
                    if key == 'city':
                        city = value
                    global expiration_date
                    if key == 'expiration_date':
                        expiration_date = value
                    global zipcode
                    if key == 'zipcode':
                        zipcode = value
                    global domain_name
                    if key == 'domain_name':
                        domain_name = value
                    global country
                    if key == 'country':
                        country = value
                    global whois_server
                    if key == 'whois_server':
                        whois_server = value
                    global state
                    if key == 'state':
                        state = value
                    global registrar
                    if key == 'registrar':
                        registrar = value
                    global referral_url
                    if key == 'referral_url':
                        referral_url = value
                    global address
                    if key == 'address':
                        address = value
                    global name_servers
                    if key == 'name_servers':
                        ns = ("</p>".join(map(str, value)))
                        name_servers = ns
                    global org
                    if key == 'org':
                        org = value
                    global creation_date
                    if key == 'creation_date':
                        creation_date = value
                    global emails
                    if key == 'emails':
                        email = ("".join(map(str, value)))
                        emails = email

                dump_all_whois = osint_whois_db(domain=domain,
                                                updated_date=updated_date,
                                                status=status,
                                                name=name,
                                                city=city,
                                                expiration_date=expiration_date,
                                                zipcode=zipcode,
                                                domain_name=domain_name,
                                                country=country,
                                                whois_server=whois_server,
                                                state=state,
                                                registrar=registrar,
                                                referral_url=referral_url,
                                                address=address,
                                                name_servers=name_servers,
                                                org=org,
                                                creation_date=creation_date,
                                                emails=emails
                                                )
                dump_all_whois.save()

                save_subdoamin = osint_domain_db(domains=domain,
                                                 project_id=project_id)
                save_subdoamin.save()

    return HttpResponseRedirect('/osintscan/domain_list/')


def whois_info(request):
    """

    :param request:
    :return:
    """
    # d = osint_whois_db.objects.all()
    # d.delete()
    all_domain = osint_domain_db.objects.all().values('domains').distinct()
    domain = ''
    name_servers = ''
    if request.method == 'GET':
        domain = request.GET['domain']

    all_whois_info = osint_whois_db.objects.filter(domain=domain)

    return render(request,
                  'domain_list.html',
                  {'all_whois_info': all_whois_info,
                   'all_domain': all_domain,
                   }
                  )


def del_osint_domain(request):
    """

    :param request:
    :return:
    """

    if request.method == "POST":
        domain = request.POST.get('domain')

        all_domains = osint_whois_db.objects.filter(domain=domain)
        all_domains.delete()
        all_osint_domain = osint_domain_db.objects.filter(domains=domain)
        all_osint_domain.delete()

    return HttpResponseRedirect('/osintscan/domain_list/')
