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

from django.urls import include, path

from cicd import views

app_name = "cicd"

urlpatterns = [
    path("", views.CicdScanList.as_view(), name="cicd_list"),
    path("scannercmd/", views.ScannerCommand.as_view(), name="scannercmd"),
    path("createpolicies/", views.CreatePolicies.as_view(), name="createpolicies"),
    path("deletepolicies/", views.PoliciesDelete.as_view(), name="deletepolicies"),
    path("policiesedit/<str:uu_id>/", views.PoliciesEdit.as_view(), name="policiesedit")
]
