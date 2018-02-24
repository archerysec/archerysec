FROM python:2.7
RUN mkdir /archerysec
WORKDIR /archerysec
ADD requirements.txt /archerysec/
RUN pip install -r requirements.txt
ADD . /archerysec/
RUN python manage.py makemigrations networkscanners
RUN python manage.py makemigrations webscanners
RUN python manage.py makemigrations projects
RUN python manage.py makemigrations APIScan
RUN python manage.py migrate