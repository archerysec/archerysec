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
        'HOST': os.getenv("DB_HOST"),
        'PORT': 5432,
    }
}

ADMINS = [
    ('admin', os.getenv('DJANGO_ADMIN_EMAIL', 'admin@example.com'))
]

EMAIL_HOST = os.getenv("EMAIL_HOST", "localhost")
EMAIL_PORT = os.getenv("EMAIL_PORT", 25)
EMAIL_SUBJECT_PREFIX = "[ArcherySec] "
