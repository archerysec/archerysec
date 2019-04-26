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

from sitetree.utils import tree, item

sitetrees = (
    tree('topnavbar', items=[
        item('API Docs',
             'https://developers.archerysec.com',
             url_as_pattern=False,
             hint="icon-link"),
        item('Settings',
             'webscanners:setting',
             access_loggedin=True,
             hint="icon-cog"),
        item('Log Out',
             'webscanners:logout',
             access_loggedin=True,
             hint="icon-share-alt")]),
)
