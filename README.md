Archerysecurity
=================

## archerysecurity - a security tool
Web and Network scanner (In Development)

![alt text](https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/archerysecurity/static/photo.png)

# Installation
git clone https://github.com/anandtiwarics/archerysecurity.git

pip install -r requirements.txt

python manage.py collectstatic

python manage.py makemigrations networkscanners

python manage.py makemigrations webscanners

python manage.py migrate

python manage.py createsuperuser

python manage.py runserver