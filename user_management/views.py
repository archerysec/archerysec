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


from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.hashers import make_password
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, get_object_or_404, render
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from user_management import permissions
from user_management.models import *
from user_management.serializers import *


class Users(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            user_profile = UserProfile.objects.all()
            serialized_data = UserProfileSerializers(user_profile, many=True)
        else:
            try:
                user_profile = UserProfile.objects.get(uu_id=uu_id)
                serialized_data = UserProfileSerializers(user_profile, many=False)
            except UserProfile.uu_id.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(serialized_data.data, status=status.HTTP_200_OK)

    def delete(self, request, uu_id):
        try:
            user_profile = UserProfile.objects.filter(uu_id=uu_id)
            content = {"message": user_profile.uu_id}
            user_profile.delete()
            return Response(content, status=status.HTTP_200_OK)
        except UserProfile.uu_id.DoesNotExist:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )

    def post(self, request):
        serializer = UserCreatReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data.get("email")
        organization = request.data.get("organization")
        password = request.data.get("password")
        role = request.data.get("role")
        name = request.data.get("name")

        user_exist = UserProfile.objects.filter(email=email).exists()
        if user_exist:
            content = {"message": "User Already Exist"}
            return Response(content, status=status.HTTP_406_NOT_ACCEPTABLE)
        else:
            user = UserProfile.objects.create_user(
                email, name, role, organization, password
            )
            content = {"message": "User Successfully Created", "user_id": user.uu_id}
            return Response(content, status=status.HTTP_200_OK)

    def put(self, request, uu_id):
        serializer = UserPutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data.get("email")
        password = make_password(request.data.get("password"))
        role = request.data.get("role")
        name = request.data.get("name")
        image = request.data.get("image")
        is_active = request.data.get("is_active")
        is_staff = request.data.get("is_staff")

        user_profile = UserProfile.objects.filter(uu_id=uu_id).update(
            email=email,
            password=password,
            role=role,
            name=name,
            image=image,
            is_active=is_active,
            is_staff=is_staff,
            organization=request.user.organization,
        )
        if user_profile > 0:
            return Response(
                {"message": "User Profile Updated"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class InviteUserAPIView(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def post(self, request):
        email = request.data.get("email")
        role = request.data.get("role")
        name = request.data.get("name")

        # Create a new user object with a random password
        password = UserProfile.objects.make_random_password()
        user = UserProfile.objects.create_user(
            email=email,
            password=password,
            organization=request.user.organization.id,
            name=name,
            role=role,
        )
        token = default_token_generator.make_token(user)
        user.pass_token = token
        user.token_time = datetime.now() + timedelta(hours=24)
        user.save()
        user.is_active = False
        user.save()
        activation_link = self.generate_activation_link(request, user)
        try:
            send_invitation_email(user.email, activation_link)
            return Response(
                {
                    "message": "User invited successfully. Please check your email for activation instructions."
                },
                status=status.HTTP_201_CREATED,
            )
        except:
            return Response(
                {
                    "message": "Email Configuration not found",
                    "activation_link": activation_link,
                }
            )

    def generate_activation_link(self, request, user):
        uid = urlsafe_base64_encode(force_bytes(user.uu_id))
        token = user.pass_token
        return request.build_absolute_uri(
            reverse("archeryapi:activate-user", kwargs={"uid": uid, "token": token})
        )


class ResetUserPasswordAPIView(APIView):
    permission_classes = (

    )

    def post(self, request):
        email = request.data.get("email")

        user = UserProfile.objects.get(
            email=email
        )
        token = default_token_generator.make_token(user)
        user.pass_token = token
        user.token_time = datetime.now() + timedelta(hours=24)
        user.save()
        activation_link = self.generate_activation_link(request, user)
        try:
            send_invitation_email(user.email, activation_link)
            return Response(
                {
                    "message": "Reset Link will be sent if user exist. Please check your email for reset instructions."
                },
                status=status.HTTP_201_CREATED,
            )
        except:
            return Response(
                {
                    "message": "Email Configuration not found",
                    "activation_link": activation_link,
                }
            )

    def generate_activation_link(self, request, user):
        uid = urlsafe_base64_encode(force_bytes(user.uu_id))
        token = user.pass_token
        return request.build_absolute_uri(
            reverse("archeryapi:reset-password", kwargs={"uid": uid, "token": token})
        )


class UserActivateAPIView(APIView):
    permission_classes = ()

    def post(self, request, uid, token):
        # Decode user ID from the URL
        user_id = force_str(urlsafe_base64_decode(uid))

        try:
            # Find the user by user_id
            user = UserProfile.objects.get(uu_id=user_id)

        except UserProfile.uu_id.DoesNotExist:
            return Response(
                {"message": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Verify the token and check if it has expired
        if user.pass_token == token and user.token_time >= datetime.now():
            # Get user data from request body
            password = request.data.get("password")

            # Activate the user and set the new password
            user.is_active = True
            user.pass_token = default_token_generator.make_token(user)
            user.set_password(password)
            user.save()

            return Response(
                {
                    "message": "Account activated successfully. You can now login with your new password."
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"message": "Invalid or expired activation link."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class UserPasswordResetAPIView(APIView):
    permission_classes = ()

    def post(self, request, uid, token):
        # Decode user ID from the URL
        user_id = force_str(urlsafe_base64_decode(uid))

        try:
            # Find the user by user_id
            user = UserProfile.objects.get(uu_id=user_id)

        except UserProfile.uu_id.DoesNotExist:
            return Response(
                {"message": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # Verify the token and check if it has expired
        if user.pass_token == token and user.token_time >= datetime.now():
            # Get user data from request body
            password = request.data.get("password")

            # Activate the user and set the new password
            user.is_active = True
            user.pass_token = default_token_generator.make_token(user)
            user.set_password(password)
            user.save()

            return Response(
                {
                    "message": "Password reset successfully. You can now login with your new password."
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"message": "Invalid or expired activation link."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class UsersList(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            user_profile = UserProfile.objects.filter()
            serialized_data = UserProfileSerializers(user_profile, many=True)
        else:
            try:
                user_profile = UserProfile.objects.filter(uu_id=uu_id)
                serialized_data = UserProfileSerializers(user_profile, many=False)
            except UserProfile.uu_id.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        if request.path[:4] == "/api":
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "users/list_users.html",
                {"all_users": user_profile},
            )

    def post(self, request):
        try:
            user_id = request.data.get("user_id")
            user_profile = UserProfile.objects.filter(uu_id=user_id)
            user_profile.delete()
            messages.success(request, "User Deleted")
            return HttpResponseRedirect("/users/list_user/")
        except UserProfile.uu_id.DoesNotExist:
            messages.error(request, "User Doesn't Exist")
            return HttpResponseRedirect("/users/list_user/")


class UsersEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "users/edit_user.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        org = Organization.objects.filter()
        if uu_id == None:
            user_details = UserProfile.objects.filter()
            serialized_data = UserPutReqSerializers(user_details, many=True)
        else:
            try:
                print(uu_id)
                user_details = UserProfile.objects.filter(uu_id=uu_id)
                serialized_data = UserPutReqSerializers(user_details, many=False)
            except UserProfile.uu_id.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(
            {
                "serializer": serialized_data,
                "user_details": user_details,
                "user_uu_id": uu_id,
                "org": org,
            }
        )

    def post(self, request, uu_id):
        serializer = UserPutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = request.data.get("email")
        password = make_password(request.data.get("password"))
        role = request.data.get("role")
        name = request.data.get("name")
        image = request.data.get("image")
        organization = request.data.get("organization")
        pass_token = request.data.get("pass_token")
        user_profile = UserProfile.objects.filter(uu_id=uu_id).update(
            email=email,
            password=password,
            role=role,
            name=name,
            image=image,
            pass_token=pass_token,
            organization=organization,
        )
        if user_profile > 0:
            return HttpResponseRedirect("/users/list_user/")
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class UsersAdd(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "users/add_user.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        org = Organization.objects.all()

        return Response({"org": org})

    def post(self, request):
        serializer = UserCreatReqSerializers(data=request.data)
        serializer.is_valid()

        email = request.data.get("email")
        organization = request.data.get("organization")
        password = request.data.get("password")
        role = request.data.get("role")
        name = request.data.get("name")

        user_exist = UserProfile.objects.filter(email=email).exists()
        if user_exist:
            messages.error(request, "User Already Exist")
            content = {"message": "User Already Exist"}
            return HttpResponseRedirect("/users/list_user/")
        else:
            UserProfile.objects.create_user(email, name, role, organization, password)
            messages.success(request, "User Created")
            return HttpResponseRedirect("/users/list_user/")


class Profile(APIView):
    # renderer_classes = [TemplateHTMLRenderer]
    # template_name = "profile/profile.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsOwnerOrAdminOnly,
    )

    def get(self, request):
        """
        Return User profile detail
        """
        id = request.user.id
        user_profile = UserProfile.objects.filter(id=id)
        serialized_data = UserProfileSerializers(user_profile, many=False)
        if request.path[:4] == "/api":
            return Response(serialized_data.data, status=status.HTTP_200_OK)
        else:
            return render(request, "profile/profile.html", {"profiles": user_profile})
        # return Response({"serializer": serializer, "profiles": user_profile})

    def put(self, request, uu_id):
        serializer = UserProfilePutReqSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        password = make_password(request.data.get("password"))
        name = request.data.get("name")
        image = request.data.get("image")

        id = request.user.id

        user_profile = UserProfile.objects.filter(id=id).update(
            password=password,
            name=name,
            image=image,
        )
        if user_profile > 0:
            return Response(
                {"message": "User Profile Updated"}, status=status.HTTP_200_OK
            )
        else:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class Roles(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsViewer,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            user_role = UserRoles.objects.all()
            serialized_data = UserRoleSerializers(user_role, many=True)
        else:
            try:
                user_role = UserRoles.objects.get(uu_id=uu_id)
                serialized_data = UserRoleSerializers(user_role, many=False)
            except UserRoles.DoesNotExist:
                return Response(
                    {"message": "User Role Exist"}, status=status.HTTP_404_NOT_FOUND
                )
        return Response(serialized_data.data, status=status.HTTP_200_OK)


class OrganizationDetail(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "organization/org_list.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        """
        Return User profile detail
        """
        organization = Organization.objects.all()
        serialized_data = OrganizationSerializers(organization, many=False)
        return Response({"serializer": serialized_data, "organization": organization})

    # Delete Organizaiton Functionality
    # def post(self, request):
    #     try:
    #         org_id = request.data.get("org_id")
    #         org_profile = Organization.objects.get(uu_id=org_id)
    #         org_profile.delete()
    #         return HttpResponseRedirect('/users/list_org/')
    #     except Organization.DoesNotExist:
    #         return Response(
    #             {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
    #         )


class OrgAdd(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "organization/org_add.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        org = Organization.objects.all()

        return Response({"org": org})

    def post(self, request):
        serializer = OrganizationSerializers(data=request.data)
        serializer.is_valid()

        name = request.data.get("name")
        description = request.data.get("description")

        save_org = Organization(name=name, description=description)
        save_org.save()
        return HttpResponseRedirect("/users/list_org/")


class OrgEdit(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "organization/org_edit.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request, uu_id=None):
        if uu_id == None:
            org_details = Organization.objects.get(uu_id=uu_id)
            serialized_data = CreateOrganizationSerializers(org_details, many=True)
        else:
            try:
                org_details = Organization.objects.get(uu_id=uu_id)
                serialized_data = CreateOrganizationSerializers(org_details, many=False)
            except UserProfile.DoesNotExist:
                return Response(template_name="error/404.html")
        return Response({"serializer": serialized_data, "org_details": org_details})

    def post(self, request, uu_id):
        serializer = CreateOrganizationSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = request.data.get("name")
        description = request.data.get("description")
        org_add = Organization.objects.filter(uu_id=uu_id).update(
            name=name,
            description=description,
        )
        if org_add > 0:
            return HttpResponseRedirect("/users/list_org/")
        else:
            return Response(
                {"message": "Org Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


def send_invitation_email(email, activation_link):
    subject = "Invitation to Activate Your Account"
    message = f"Please click the following link to activate your account and set a new password:\n{activation_link}"
    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
