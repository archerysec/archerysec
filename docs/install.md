# Installation #
=================

<pre>
$ git clone https://github.com/anandtiwarics/archerysecurity.git
$ cd /archerysecurity
$ pip install -r requirements.txt
$ python manage.py collectstatic
$ python manage.py makemigrations networkscanners
$ python manage.py makemigrations webscanners
$ python manage.py migrate
$ python manage.py createsuperuser
$ python manage.py runserver
</pre>