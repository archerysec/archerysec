from django.conf.urls import url
from . import views

app_name = 'APIScan'

urlpatterns = [
    url(r'^$', views.list_api_scan, name='listscan'),
    url(r'^create/$', views.add_api_scan, name='addapiscan'),
    url(r'^del_scan/$', views.del_api_scan, name='del_scan'),
    url(r'api_scan_auth/$', views.authenticate, name='authenticate'),
    url(r'api_scan_url/$', views.url_api_scan, name='api_scan_url'),
    url(r'api_scan_edit/$', views.edit_scan, name='api_scan_edit')

]
