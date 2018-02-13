from django.conf.urls import url
from Dashboard import views

app_name = 'Dashboard'

urlpatterns = [
    url(r'^$', views.dash_call, name='zap_vuln_chart'),
    url(r'^dashboard/$', views.dash_call, name='dashboard'),
    url(r'^project_dashboard/$', views.project_dashboard, name='project_dashboard'),
    url(r'^web_dashboard/$', views.web_dashboard, name='web_dashboard'),
    url(r'^net_dashboard/$', views.net_dashboard, name='net_dashboard'),
    url(r'^proj_data/$', views.proj_data, name='proj_data'),
    url(r'^web_dash_data/$', views.web_dash_data, name='web_dash_data'),
    url(r'^net_dash_data/$', views.net_dash_data, name='net_dash_data')

]