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

import hashlib

from django.shortcuts import HttpResponse, HttpResponseRedirect, render
from django.urls import reverse

from compliance.models import DockleScanDb, DockleScanResultsDb
from staticscanners.resources import dockleResource
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework import status
from rest_framework.response import Response
from user_management import permissions


def export(request):
    """
    :param request:
    :return:
    """

    if request.method == "POST":
        scan_id = request.POST.get("scan_id")
        report_type = request.POST.get("type")

        dockle_resource = dockleResource()
        queryset = DockleScanResultsDb.objects.filter(scan_id=scan_id
                                                      )
        dataset = dockle_resource.export(queryset)
        if report_type == "csv":
            response = HttpResponse(dataset.csv, content_type="text/csv")
            response["Content-Disposition"] = 'attachment; filename="%s.csv"' % scan_id
            return response
        if report_type == "json":
            response = HttpResponse(dataset.json, content_type="application/json")
            response["Content-Disposition"] = 'attachment; filename="%s.json"' % scan_id
            return response
        if report_type == "yaml":
            response = HttpResponse(dataset.yaml, content_type="application/x-yaml")
            response["Content-Disposition"] = 'attachment; filename="%s.yaml"' % scan_id
            return response


class DockleScanList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'compliance/dockle/docklescans_list.html'

    permission_classes = (
        IsAuthenticated,
    )

    def get(self, request):
        all_dockle_scan = DockleScanDb.objects.filter()

        return render(
            request, "compliance/dockle/docklescans_list.html", {"all_dockle_scan": all_dockle_scan}
        )


class DockleVulnList(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'compliance/dockle/docklescan_list_vuln.html'

    permission_classes = (
        IsAuthenticated,
    )

    def get(self, request):
        scan_id = request.GET["scan_id"]

        dockle_all_vuln = DockleScanResultsDb.objects.filter(scan_id=scan_id
                                                             )
        dockle_all_audit = DockleScanResultsDb.objects.filter(scan_id=scan_id
                                                              )

        all_compliance = DockleScanDb.objects.filter(scan_id=scan_id)

        return render(
            request,
            "compliance/dockle/docklescan_list_vuln.html",
            {
                "dockle_all_vuln": dockle_all_vuln,
                "dockle_all_audit": dockle_all_audit,
                "all_compliance": all_compliance,
            },
        )


class DockleVulnData(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'compliance/dockle/docklescan_vuln_data.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAnalyst
    )

    def get(self, request):
        scan_id = request.GET["scan_id"]
        vuln_id = request.GET["vuln_id"]
        dockle_vuln_data = DockleScanResultsDb.objects.filter(
            scan_id=scan_id,
            vuln_id=vuln_id,
            vuln_status="Open",
            false_positive="No",
        )

        vuln_data_closed = DockleScanResultsDb.objects.filter(
            scan_id=scan_id,
            vuln_id=vuln_id,
            vuln_status="Closed",
            false_positive="No",
        )
        false_data = DockleScanResultsDb.objects.filter(scan_id=scan_id, vuln_id=vuln_id, false_positive="Yes"
                                                        )

        return render(
            request,
            "compliance/dockle/docklescan_vuln_data.html",
            {
                "dockle_vuln_data": dockle_vuln_data,
                "false_data": false_data,
                "vuln_data_closed": vuln_data_closed,
            },
        )

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        DockleScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id
                                           ).update(false_positive=false_positive, vuln_status=status)

        if false_positive == "Yes":
            vuln_info = DockleScanResultsDb.objects.filter(scan_id=scan_id, vuln_id=vuln_id
                                                           )
            for vi in vuln_info:
                Name = vi.Name
                NamespaceName = vi.NamespaceName
                Severity = vi.Severity
                dup_data = Name + Severity + NamespaceName
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                DockleScanResultsDb.objects.filter(vuln_id=vuln_id, scan_id=scan_id
                                                   ).update(
                    false_positive=false_positive,
                    vuln_status=status,
                    false_positive_hash=false_positive_hash,
                )

        return HttpResponseRedirect(
            reverse("dockle:dockle_vuln_data")
            + "?scan_id=%s&test_name=%s" % (scan_id, vuln_id)
        )


class DockleDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = 'compliance/dockle/dockle_vuln_details.html'

    permission_classes = (
        IsAuthenticated,
    )

    def get(self, request):
        scan_id = request.GET["scan_id"]
        vuln_id = request.GET["vuln_id"]

        dockle_vuln_details = DockleScanResultsDb.objects.filter(scan_id=scan_id, vuln_id=vuln_id
                                                                 )
        return render(
            request,
            "compliance/dockle/dockle_vuln_details.html",
            {
                "dockle_vuln_details": dockle_vuln_details,
            },
        )


class DockleDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'compliance/dockle/docklescans_list.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAnalyst,
    )

    def post(self, request):
        scan_id = request.POST.get("scan_id")
        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            item = DockleScanDb.objects.filter(scan_id=scan_id)
            item.delete()
            item_results = DockleScanResultsDb.objects.filter(scan_id=scan_id
                                                              )
            item_results.delete()
        # messages.add_message(request, messages.SUCCESS, 'Deleted Scan')
        return HttpResponseRedirect(reverse("dockle:dockle_list"))


class DockleVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = 'compliance/dockle/dockle_vuln_details.html'

    permission_classes = (
        IsAuthenticated,
        permissions.IsAnalyst
    )

    def post(self, request):
        vuln_id = request.POST.get(
            "del_vuln",
        )
        scan_id = request.POST.get(
            "scan_id",
        )
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        print("split_length"), split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = DockleScanResultsDb.objects.filter(vuln_id=vuln_id
                                                             )
            delete_vuln.delete()
        all_dockle_data = DockleScanResultsDb.objects.filter(scan_id=scan_id
                                                             )

        total_vul = len(all_dockle_data)
        total_high = len(all_dockle_data.filter(Severity="High"))
        total_medium = len(all_dockle_data.filter(Severity="Medium"))
        total_low = len(all_dockle_data.filter(Severity="Low"))
        total_duplicate = len(all_dockle_data.filter(vuln_duplicate="Yes"))

        DockleScanDb.objects.filter(scan_id=scan_id).update(
            total_vuln=total_vul,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            total_dup=total_duplicate,
        )

        return HttpResponseRedirect(
            reverse("dockle:dockle_all_vuln" + "?scan_id=%s" % scan_id)
        )
