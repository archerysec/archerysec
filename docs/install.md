# Getting started

## Installation

## Installing Archery

Before installing Archery, you need to make sure you have Python and `pip`
– the Python package manager – up and running. You can verify if you're already
good to go with the following commands:

``` sh
python --version
# Python 2.7.13
pip --version
# pip 9.0.1
```


Now clone Archery tool from github

``` sh
git clone https://github.com/archerysec/archerysec.git
```

Move to directory archerysec

``` sh
cd /archerysec
```

Install requirements
``` sh
pip install -r requirements.txt
```

Load static files
``` sh
python manage.py collectstatic
```

Makemigrations of all networkscanners app models
``` sh
python manage.py makemigrations networkscanners
```
Makemigrations of all webscanners app models
``` sh
python manage.py makemigrations webscanners
```

Makemigrations of all projects app models
```sh
python manage.py makemigrations projects
```

Migrate all data
``` sh
python manage.py migrate
```

Now you need to create application Credentials
``` sh
python manage.py createsuperuser
```

Let's run the application
``` sh
python manage.py runserver
```


