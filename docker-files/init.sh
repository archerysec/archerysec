#!/bin/bash

export DJANGO_DEBUG=1

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

echo "Checking Variables"
if [ -z "$NAME" ]
then
      echo "\$NAME is empty, Please Provide User Name. Ex NAME=user"
      exit 1
else
      echo "\$NAME Found"
fi

if [ -z "$EMAIL" ]
then
      echo "\$EMAIL is empty, Please Provide User Name. Ex EMAIL=user@user.com"
      exit 1
else
      echo "\$EMAIL Found"
fi

if [ -z "$PASSWORD" ]
then
      echo "\$PASSWORD is empty, Please Provide User Name. Ex PASSWORD=userpassword"
      exit 1
else
      echo "\$PASSWORD Found"
fi


if [ "$ARCHERY_WORKER" = "True" ]
then
    python3 -u manage.py process_tasks -v 3 --traceback
else
    python3 manage.py makemigrations
    python3 manage.py migrate --noinput
    python3 manage.py initadmin
    echo 'Apply Fixtures'
    python3 manage.py loaddata fixtures/default_user_roles.json
    python3 manage.py loaddata fixtures/default_organization.json
    echo "from user_management.models import UserProfile; UserProfile.objects.create_superuser(name='${NAME}', email='${EMAIL}', password='${PASSWORD}', role=1, organization=1)" | python manage.py shell
    echo '================================================================='
    echo 'User Created'
    echo 'User Name :' ${NAME}
    echo 'User Email': ${EMAIL}
    echo 'Role : Admin'
    echo 'Done !'
    echo "Now running application"
    exec gunicorn -b 0.0.0.0:8000 archerysecurity.wsgi:application --workers=1 --threads=10 --timeout=1800
fi
