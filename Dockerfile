FROM python:2.7
RUN mkdir /root/archerysec
WORKDIR /root/archerysec
ADD requirements.txt /root/archerysec
RUN pip install -r requirements.txt
COPY . /root/archerysec/

RUN python manage.py makemigrations networkscanners
RUN python manage.py makemigrations webscanners
RUN python manage.py makemigrations projects
RUN python manage.py makemigrations APIScan
RUN python manage.py migrate

EXPOSE 8000

WORKDIR /root/archerysec/

CMD ["python","manage.py","runserver","0.0.0.0:8000"]

CMD ["python","manage.py","process_tasks"]
