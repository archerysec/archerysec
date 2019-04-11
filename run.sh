#!/bin/bash
#export TIME_ZONE='Asia/Kolkata'

. venv/bin/activate && python manage.py process_tasks &

# Prod Server
. venv/bin/activate && gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --timeout=1800
