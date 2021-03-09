#!/bin/bash

export DJANGO_DEBUG=1

source /home/archerysec/app/venv/bin/activate

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


if [ "$ARCHERY_WORKER" = "True" ]
then
    python3 -u manage.py process_tasks -v 3 --traceback
else
    python3 manage.py migrate sitetree --noinput
    python3 manage.py migrate --noinput
    python3 manage.py initadmin

    gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --threads=10 --timeout=1800
fi
