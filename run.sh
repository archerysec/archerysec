#!/bin/bash
#export TIME_ZONE='Asia/Kolkata'
# Prod Server
. venv/bin/activate && gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --timeout=1800
