Archerysecurity
=================

## archerysecurity - a security tool
Web and Network scanner (In Development)

<img src="https://raw.githubusercontent.com/anandtiwarics/archerysecurity/master/archerysecurity/static/photo.png" alt="alt text" width="40" height="100">

# Installation
git clone https://github.com/anandtiwarics/archerysecurity.git

pip install -r requirements.txt

python manage.py collectstatic

python manage.py makemigrations networkscanners

python manage.py makemigrations webscanners

python manage.py migrate

python manage.py createsuperuser

python manage.py runserver