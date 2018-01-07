Archery
=================
Archery is an opensource vulnerability assessment and management tool which helps developers and pentesters to perform scans and manage vulnerabilities. Archery uses popular opensource tools to perform comprehensive scaning for web application and network. It also performs web application dynamic authenticated scanning and covers the whole applications by using selenium. The developers can also utilize the tool for implementation of their DevOps CI/CD environment.


## Archery
Open Source Vulnerability Assessment and Management (In Development)


<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/archerysecurity/static/photo.png">
</p>

### Documentation

> [https://anandtiwarics.github.io/archerysec/](https://anandtiwarics.github.io/archerysec/)

## Demo
![Demo](https://github.com/anandtiwarics/photoVideos/blob/master/Photos/archery_demo.gif)


## Overview of the tool:
* Perform Web and Network vulnerability Scanning using opensource tools.
* Correlates and Collaborate all raw scans data, show them in a consolidated manner.
* Perform authenticated web scanning.
* Perform web application scanning using selenium.
* Vulnerability Managment.
* Enable REST API's for developers to perform scaning and Vulnerability Managment.
* Useful for DevOps teams for Vulnerability Managment.

## Note
Currently project is in developement phase and still lot of work going on.

## Requirement

* Python 2.7
* OpenVas 8
* OWASP ZAP 2.7.0 (https://github.com/zaproxy/zaproxy/wiki/Downloads)
* Selenium Python (Firefox Webdriver) (https://github.com/mozilla/geckodriver/releases)

## Installation

<pre>
$ git clone https://github.com/anandtiwarics/archerysec.git
$ cd /archerysec
$ pip install -r requirements.txt
$ python manage.py collectstatic
$ python manage.py makemigrations networkscanners
$ python manage.py makemigrations webscanners
$ python manage.py makemigrations projects
$ python manage.py migrate
$ python manage.py createsuperuser
$ python manage.py runserver
</pre>

Note: Make sure these steps (except createsuperuser) should be perform after every git pull.

## Setup Setting

Zap Setting

1. Go to Setting Page
2. Edit ZAP setting or navigate URL : http://host:port/setting_edit/
3. Fill all required information and click on save.

OpenVAS Setting

1. Go to setting Page
2. Edit OpenVAS setting or navigate URL : http://host:port/networkscanners/openvas_setting
3. Fill all required information and click on save.


### Road Map

* API Automated vulnerability scanning.
* Perform Reconnaissance before scanning.
* Concurrent Scans.
* Vulnerability POC pictures.
* Cloud Security scanning.
* Dashboards
* Easy to installing.

### Lead Developer

Anand Tiwari -  https://github.com/anandtiwarics

### Social Media
* [Official Website](https://anandtiwarics.github.io/archerysec/)
* [Twitter](https://twitter.com/archerysec)
* [Facebook](https://facebook.com/archerysec)