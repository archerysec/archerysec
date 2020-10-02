@echo off
set DJANGO_DEBUG=1

.\venv\Scripts\activate && waitress-serve --listen=*:8000 --threads=10 --channel-timeout=1800 archerysecurity.wsgi:application