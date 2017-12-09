Archerysecurity
=================

## archerysecurity - a security tool
Web and Network scanner (In Development)

<p align="center">
  <img width="350" height="100" src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/archerysecurity/static/photo.png">
</p>

# Installation
<code>$ git clone https://github.com/anandtiwarics/archerysecurity.git</code>

<code>$ pip install -r requirements.txt</code>

<code>$ python manage.py collectstatic</code>

<code>$ python manage.py makemigrations networkscanners</code>

<code>$ python manage.py makemigrations webscanners</code>

<code>$ python manage.py migrate</code>

<code>$ python manage.py createsuperuser</code>

<code>$ python manage.py runserver</code>