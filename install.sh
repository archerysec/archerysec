pip install -r requirements.txt
rm -rf /root/.cache
yes yes | python manage.py collectstatic
python manage.py migrate
python manage.py initadmin
python manage.py process_tasks &
