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
    findbugs_scan_results_db, clair_scan_results_db
from compliance.models import inspec_scan_results_db, inspec_scan_db


class DependencyResource(resources.ModelResource):
    class Meta:
        model = dependencycheck_scan_results_db


class FindbugResource(resources.ModelResource):
    class Meta:
        model = findbugs_scan_results_db


class ClairResource(resources.ModelResource):
    class Meta:
        model = clair_scan_results_db


class InspecResource(resources.ModelResource):
    class Meta:
        model = inspec_scan_results_db

