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

from import_export import resources
from staticscanners.models import dependencycheck_scan_results_db, \
    findbugs_scan_results_db, clair_scan_results_db, trivy_scan_results_db, npmaudit_scan_results_db, \
    nodejsscan_scan_results_db, tfsec_scan_db, tfsec_scan_results_db, whitesource_scan_results_db, \
    checkmarx_scan_results_db, gitlabsca_scan_results_db, gitlabsast_scan_results_db, semgrepscan_scan_results_db
from compliance.models import inspec_scan_results_db, dockle_scan_results_db


class DependencyResource(resources.ModelResource):
    class Meta:
        model = dependencycheck_scan_results_db


class FindbugResource(resources.ModelResource):
    class Meta:
        model = findbugs_scan_results_db


class ClairResource(resources.ModelResource):
    class Meta:
        model = clair_scan_results_db


class TrivyResource(resources.ModelResource):
    class Meta:
        model = trivy_scan_results_db


class NpmauditResource(resources.ModelResource):
    class Meta:
        model = npmaudit_scan_results_db


class nodejsscanResource(resources.ModelResource):
    class Meta:
        model = nodejsscan_scan_results_db


class tfsecResource(resources.ModelResource):
    class Meta:
        model = tfsec_scan_results_db


class whitesourceResource(resources.ModelResource):
    class Meta:
        model = whitesource_scan_results_db


class checkmarxResource(resources.ModelResource):
    class Meta:
        model = checkmarx_scan_results_db


class InspecResource(resources.ModelResource):
    class Meta:
        model = inspec_scan_results_db


class dockleResource(resources.ModelResource):
    class Meta:
        model = dockle_scan_results_db


class GitlabsastResource(resources.ModelResource):
    class Meta:
        model = gitlabsast_scan_results_db


class GitlabcontainerscanResource(resources.ModelResource):
    class Meta:
        model = gitlabsast_scan_results_db


class GitlabscaResource(resources.ModelResource):
    class Meta:
        model = gitlabsca_scan_results_db


class SemgrepResource(resources.ModelResource):
    class Meta:
        model = semgrepscan_scan_results_db
