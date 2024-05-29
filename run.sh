#!/bin/bash
#export TIME_ZONE='Asia/Kolkata'
# Prod Server
export DJANGO_DEBUG=1
python3 -m poetry run gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --threads=10 --timeout=1800
