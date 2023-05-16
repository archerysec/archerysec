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
# Modified by Victor Sallard (vsallard@scaleway.com)
#
# This file is part of ArcherySec Project.

import glob
import importlib
import os

from django.template.defaulttags import register

parser_function_dict = {}

# Import all modules in the scanner_parser folder
module_paths = glob.glob("./scanners/scanner_parser/*/*.py", recursive=True)
for module_path in module_paths:
    if os.path.basename(module_path) != "__init__.py":
        module_name = os.path.normpath(module_path).split(".py")[0].replace("/", ".")
        module_id = importlib.import_module(module_name)
        parser_function_dict.update(module_id.parser_header_dict)

# Create a reverse parser dict to ease the lookup for icons
icon_dict = {}
for parser_code in parser_function_dict:
    if "dbname" in parser_function_dict[parser_code]:
        dbName = parser_function_dict[parser_code]["dbname"]
    else:
        dbName = parser_function_dict[parser_code]["dbtype"]

    icon_dict[dbName] = {}
    icon_dict[dbName]["displayName"] = parser_function_dict[parser_code]["displayName"]
    icon_dict[dbName]["codeName"] = parser_code
    icon_dict[dbName]["type"] = parser_function_dict[parser_code]["type"]

    if "icon" in parser_function_dict[parser_code]:
        icon_dict[dbName]["icon"] = parser_function_dict[parser_code]["icon"]

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
    return {"PARSER_DICT": icon_dict}


@register.filter
def get_icon(dictionary, key):
    return dictionary.get(key, {}).get("icon", "/static/tools/unknown.png")


@register.filter
def get_displayName(dictionary, key):
    return dictionary.get(key, {}).get("displayName", "Unknown display name")


@register.filter
def get_codeName(dictionary, key):
    return dictionary.get(key, {}).get("codeName", "Unknown name")


@register.filter
def get_type(dictionary, key):
    return dictionary.get(key, {}).get("type", "Unknown type")
