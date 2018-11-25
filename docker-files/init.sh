#!/bin/bash

python manage.py collectstatic --noinput
python manage.py migrate --noinput
python manage.py initadmin

if [ "$ARCHERY_WORKER" = "True" ]
then
    python manage.py process_tasks
else
    python manage.py runserver 0.0.0.0:8000
fi
