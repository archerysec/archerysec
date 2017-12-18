from django.conf.urls import url
from . import views

app_name = 'webscanners'

urlpatterns = [
    url(r'^login/$', views.login, name='login'),
    url(r'^auth/$', views.auth_view, name='auth'),
    url(r'^logout/$', views.logout, name='logout'),
    url(r'^loggedin/$', views.loggedin, name='loggedin'),
    url(r'^$', views.index, name='index'),
    url(r'^vuln_list/', views.scan_list, name='vuln_list'),
    url(r'^vuln_details/', views.vuln_details, name='vuln_details'),
    url(r'^setting/', views.setting, name='setting'),
    url(r'^zapsetting/', views.zap_setting, name='zap_setting'),
    url(r'^setting_edit/', views.zap_set_update, name='setting_edit'),
    url(r'^scans_list', views.scan_list, name='setting'),
    url(r'^scans_table', views.scan_table, name='scans_table'),
    url(r'^del_scan', views.del_scan, name='del_scan'),
    url(r'^zap_vul_details', views.vuln_details, name='zap_vul_details'),
    url(r'^dashboard', views.dashboard, name='dashboard'),
    url(r'^sel_login', views.sel_login, name='sel'),
    url(r'save_cookie', views.save_cookie, name='save_cookie'),
    url(r'exclude_url', views.exclude_url, name='exclude_url'),
    url(r'^edit_vuln', views.edit_vuln, name='edit_vuln'),
    url(r'^del_vuln', views.del_vuln, name='del_vuln'),
]
