# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2022 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import importlib
import glob
import os

from django.template.defaulttags import register

ParserFunctionDict = {}

# Import all modules in the scanner_parser folder
modulePaths = glob.glob("./scanners/scanner_parser/*/*.py", recursive=True)
for modulePath in modulePaths:
    if os.path.basename(modulePath) != '__init__.py':
        moduleName = os.path.normpath(modulePath).split('.py')[0].replace("/", ".")
        moduleID = importlib.import_module(moduleName)
        ParserFunctionDict.update(moduleID.ParserHeaderDict)

# Create a reverse parser dict to ease the lookup for icons
IconDict = {}
for parserCode in ParserFunctionDict:
    if "dbname" in ParserFunctionDict[parserCode]:
        dbName = ParserFunctionDict[parserCode]["dbname"]
    else:
        dbName = ParserFunctionDict[parserCode]["dbtype"]

    IconDict[dbName] = {}
    IconDict[dbName]["displayName"] = ParserFunctionDict[parserCode]["displayName"]
    IconDict[dbName]["codeName"] = parserCode
    IconDict[dbName]["type"] = ParserFunctionDict[parserCode]["type"]

    if "icon" in ParserFunctionDict[parserCode]:
        IconDict[dbName]["icon"] = ParserFunctionDict[parserCode]["icon"]

# Jira
# IconDict["Jira"] = {
#     "icon": "/static/tools/jira.png",
#     "displayName": "Jira",
#     "codeName": "jira"
# }
# Email
# IconDict["Email"] = {
#     "icon": "/static/tools/email.png",
#     "displayName": "Email",
#     "codeName": "email"
# }


# Django specific definitions
def parser_dict(request):
    # return the value you want as a dictionnary. you may add multiple values in there.
    return {'PARSER_DICT': IconDict}


@register.filter
def get_icon(dictionary, key):
    return dictionary.get(key).get("icon")


@register.filter
def get_displayName(dictionary, key):
    return dictionary.get(key).get("displayName")


@register.filter
def get_codeName(dictionary, key):
    return dictionary.get(key).get("codeName")


@register.filter
def get_type(dictionary, key):
    return dictionary.get(key).get("type")
