pip install -r requirements.txt
yes yes | python manage.py collectstatic
python manage.py makemigrations
python manage.py migrate
python manage.py initadmin
