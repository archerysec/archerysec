import os
from .base import *

INTERNAL_IPS = [
    '172.26.0.1',
    '127.0.0.1'
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv("DB_NAME"),
        'USER': os.getenv("DB_USER"),
        'PASSWORD': os.getenv("DB_PASSWORD"),
        'HOST': 'db',
        'PORT': 5432,
    }
}

ADMINS = [
    ('admin', os.getenv('DJANGO_ADMIN_EMAIL', 'admin@example.com'))
]
