import os
from .base import *

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.getenv("DB_NAME"),
        'USER': os.getenv("DB_USER"),
        'PASSWORD': os.getenv("DB_PASSWORD"),
        'HOST': os.getenv("DB_HOST"),
        'PORT': 5432,
    }
}

ADMINS = [
    ('admin', os.getenv('DJANGO_ADMIN_EMAIL', 'admin@example.com'))
]
