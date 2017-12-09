# archerysecurity
Web and Network scanner

# Installation
git clone https://github.com/anandtiwarics/archerysecurity.git

pip install -r requirements.txt
python manage.py collectstatic
python manage.py makemigrations networkscanners
python manage.py makemigrations webscanners
python manage.py migrate
python manage.py 