Archerysecurity
=================
Archery is an opensource vulnerability assessment and management tool which helps developers and pentesters to scan and manage vulnerabilities. Archery uses popular opensource tools to perform comprehensive scans for web application and network. It also performs web application dynamic authenticated scanning and covers the whole applications by using selenium based spider. The developers can also utilize the tool for implementation of CI/CD into their environment.

## archerysecurity - a security tool
Vulnerability Assessment Tool (In Development)


<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/archerysecurity/static/photo.png">
</p>

# Demo
![Demo](https://github.com/anandtiwarics/archerysecurity/blob/master/Photos/archery_demo.gif)


# Overview of the tool:
* Vulnerability Assessment Web Application Tool.
* Perform Web and Network vulnerability Scanning using opensource tools.
* Perform authenticated web scanning.
* Perform scanning using selenium.
* Manage scans and vulnerabilities.
* Add and remove vulnerabilities.

## Note
Currently project is in developement phase and still lot of work going on.

## Requirement

* Python 2.7
* OpenVas 8 
* OWASP ZAP 2.7.0 (https://github.com/zaproxy/zaproxy/wiki/Downloads)
* Selenium Python (Firefox Webdriver) (https://github.com/mozilla/geckodriver/releases)

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
