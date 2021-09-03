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

from __future__ import unicode_literals

from django.contrib import admin

from tools import models

admin.site.register(models.NiktoResultDb)
admin.site.register(models.NmapResultDb)
admin.site.register(models.NmapScanDb)
admin.site.register(models.NmapVulnersPortResultDb)
admin.site.register(models.SslscanResultDb)
