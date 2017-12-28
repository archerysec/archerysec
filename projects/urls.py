from django.conf.urls import url
from . import views

app_name = 'projects'

urlpatterns = [
    url(r'^create/$', views.create, name='create'),
    url(r'^create_form/$', views.create_form, name='create'),
    url(r'^$', views.projects, name='projects'),
]
