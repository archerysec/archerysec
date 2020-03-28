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

Copy sample settings and modify as needed

``` sh
cp archerysecurity/local_settings.sample.py archerysecurity/local_settings.py
```

Install requirements
``` sh
pip install -r requirements.txt
```

Load static files
``` sh
python manage.py collectstatic
```

Migrate all data
``` sh
python manage.py migrate
```

Now you need to create application Credentials
``` sh
python manage.py createsuperuser
```

Or you could auto create the superuser executing. This command uses the ADMINS
setting to create the admin accounts so remember to set some username first.
Default password is "admin". REMEMBER TO CHANGE IT!
``` sh
python manage.py initadmin
```

Let's run the application
``` sh
python manage.py runserver
```
