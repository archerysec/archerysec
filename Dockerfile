FROM python:2.7
RUN mkdir /archeryproject
WORKDIR /archeryproject
ADD requirements.txt /archeryproject/
RUN pip install -r requirements.txt
ADD . /archeryproject/
RUN python manage.py makemigrations networkscanners
RUN python manage.py makemigrations webscanners
RUN python manage.py makemigrations projects
RUN python manage.py makemigrations APIScan
RUN python manage.py migrate