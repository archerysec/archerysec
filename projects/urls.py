from django.conf.urls import url
from . import views
from webscanners.web_views import dashboard

app_name = 'projects'

urlpatterns = [
    url(r'^$', dashboard, name='home'),
    url(r'^projects/create/$', views.create, name='create'),
    url(r'^projects/create_form/$', views.create_form, name='create'),
    url(r'^projects/$', views.projects, name='projects'),
    url(r'^projects/projects_view/$', views.projects_view, name='projects_view'),
    url(r'^projects/add_scan/$', views.add_scan, name='add_scan'),
    url(r'^projects/add_scan_v/$', views.add_scan_v, name='add_scan_v'),
]
