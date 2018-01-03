from django.conf.urls import url
from . import views

app_name = 'projects'

urlpatterns = [
    url(r'^create/$', views.create, name='create'),
    url(r'^create_form/$', views.create_form, name='create'),
    url(r'^$', views.projects, name='projects'),
    url(r'^projects_view/$', views.projects_view, name='projects_view'),
    url(r'^add_scan/$', views.add_scan, name='add_scan'),
    url(r'^add_scan_v/$', views.add_scan_v, name='add_scan_v'),
    url(r'^launch_scan/$', views.launch_scan, name='launch_scan'),
]
