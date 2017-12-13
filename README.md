Archerysecurity
=================

## archerysecurity - a security tool
Vulnerability Assessment Tool (In Development)

<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/archerysecurity/static/photo.png">
</p>

# Overview of the tool:
* Vulnerability Assessment Web Application Tool.
* Perform Web and Network vulnerability Scanning using opensource tools.
* Perform authenticated web scanning.
* Perform scanning using selenium.

## Note
Currently project is in developement phase and still lot of work going on.

## Requirement

* Python 2.7
* OpenVas 8
* OWASP ZAP 2.7.0
* Selenium Python (Firefox Webdriver)

# Installation #

<pre>
$ git clone https://github.com/anandtiwarics/archerysecurity.git
$ pip install -r requirements.txt
$ python manage.py collectstatic
$ python manage.py makemigrations networkscanners
$ python manage.py makemigrations webscanners
$ python manage.py migrate
$ python manage.py createsuperuser
$ python manage.py runserver
</pre>

# Road Map
* REST API implementation.
* API vulnerability scanning.
* Perform Reconnaissance before scanning.
* Concurrent Scans
* CI/CD implementation.
* Easy to installing

# Screenshots

Domain Scan

<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/Photos/domain_Scan.png">
</p>

Scan List

<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/Photos/scan_list.png">
</p>

Vulnerabilities List

<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/Photos/vuln_list.png">
</p>
