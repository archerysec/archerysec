pip install -r requirements.txt
yes yes | python manage.py collectstatic
python manage.py migrate
python manage.py initadmin
