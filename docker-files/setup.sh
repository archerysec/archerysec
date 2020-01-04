#!/bin/bash

python3 manage.py collectstatic --noinput

# wait for Postgres to be available
if [ -z "$DB_HOST" ]
then
    echo "not running posgres"
else
  until PGPASSWORD=$DB_PASSWORD psql -h "$DB_HOST" -U "$DB_USER" -c '\q'; do
    >&2 echo "Postgres is unavailable - sleeping"
    sleep 1
  done

  >&2 echo "Postgres is up - executing migrations"
  exec $cmd
fi

python3 manage.py migrate --noinput

gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --threads=10 --timeout=1800
