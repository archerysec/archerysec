# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, render_to_response, HttpResponse, HttpResponseRedirect
from projects.models import project_db
from django.contrib import messages


# Create your views here.


def create_form(request):
    return render(request, 'project_create.html')


def create(request):
    if request.method == 'POST':
        project_name = request.POST.get("projectname")
        project_date = request.POST.get("projectstart")
        project_end = request.POST.get("projectend")
        project_owner = request.POST.get("projectowner")

        save_project = project_db(project_name=project_name, project_start=project_date, project_end=project_end,
                                  project_owner=project_owner)
        save_project.save()

        messages.success(request, "Project Created")

        # return HttpResponseRedirect(reversed('project_create.html'))
    return render(request, 'project_create.html')


def projects(request):
    all_projects = project_db.objects.all()

    return  render(request, 'projects.html', {'all_projects': all_projects})
