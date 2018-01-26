from django.conf.urls import url
from . import web_views

app_name = 'webscanners'

urlpatterns = [
    url(r'^login/$', web_views.login, name='login'),
    url(r'^auth/$', web_views.auth_view, name='auth'),
    url(r'^logout/$', web_views.logout, name='logout'),
    url(r'^loggedin/$', web_views.loggedin, name='loggedin'),
    url(r'^$', web_views.index, name='index'),
    url(r'^vuln_list/', web_views.scan_list, name='vuln_list'),
    url(r'^web_vuln_list/', web_views.list_web_vuln, name='web_vuln'),
    url(r'^vuln_details/', web_views.vuln_details, name='vuln_details'),
    url(r'^setting/', web_views.setting, name='setting'),
    url(r'^zapsetting/', web_views.zap_setting, name='zap_setting'),
    url(r'^setting_edit/', web_views.zap_set_update, name='setting_edit'),
    url(r'^scans_list', web_views.scan_list, name='setting'),
    url(r'^scans_table', web_views.scan_table, name='scans_table'),
    url(r'^del_scan', web_views.del_scan, name='del_scan'),
    url(r'^zap_vul_details', web_views.vuln_details, name='zap_vul_details'),
    url(r'^dashboard', web_views.dashboard, name='dashboard'),
    url(r'^sel_login', web_views.sel_login, name='sel'),
    url(r'save_cookie', web_views.save_cookie, name='save_cookie'),
    url(r'exclude_url', web_views.exclude_url, name='exclude_url'),
    url(r'^edit_vuln', web_views.edit_vuln, name='edit_vuln'),
    url(r'^del_vuln', web_views.del_vuln, name='del_vuln'),
    url(r'^vuln_dat', web_views.vuln_check, name='vuln_dat'),
    url(r'^edit_vuln_dat', web_views.edit_vuln_check, name='edit_vuln_dat'),
    url(r'^add_vuln', web_views.add_vuln, name='add_vuln'),
    url(r'^create_vuln', web_views.create_vuln, name='create_vuln'),
    # url(r'scan/', web_views.index, name='scanapi')

]
