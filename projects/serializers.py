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

from rest_framework import serializers


class ProjectDataSerializers(serializers.Serializer):

    project_id = serializers.UUIDField(read_only=True)
    project_name = serializers.CharField(required=True,
                                         help_text="Project Name")
    project_disc = serializers.CharField(required=True,
                                         help_text="Project Description")
    project_start = serializers.DateField(required=False,
                                          help_text="Project start date")
    project_end = serializers.DateField(required=False,
                                        help_text="Project End date")
    project_owner = serializers.CharField(required=False,
                                          help_text="Project Owner")
