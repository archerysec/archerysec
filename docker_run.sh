pip install -r requirements.txt
yes yes | python manage.py collectstatic
python manage.py makemigrations networkscanners
python manage.py makemigrations webscanners
python manage.py makemigrations projects
python manage.py makemigrations APIScan
python manage.py makemigrations osintscan
python manage.py makemigrations jiraticketing
python manage.py makemigrations tools
python manage.py makemigrations manual_scan
python manage.py migrate
python manage.py process_tasks &