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

from django.urls import path
from rest_framework_simplejwt import views as jwt_views

from authentication import views

urlpatterns = [
    # Your URLs...
    # path("login/", views.MyTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("refresh-token/", jwt_views.TokenRefreshView.as_view(), name="token_refresh"),
    path("forgot-pass/", views.ForgotPassword.as_view()),
    path("reset-pass/", views.ResetPassword.as_view()),
    path("update-pass/", views.UpdatePassword.as_view()),
    path("user-settings/", views.UserSettings.as_view()),
    # path("logout/", views.Logout.as_view()),
    path("login/", views.login, name="login"),
    path("auth/", views.auth_view, name="auth"),
    path("logout/", views.logout, name="logout"),
    path("loggedin/", views.loggedin, name="loggedin"),
]
