FROM python:2.7
RUN mkdir /root/archerysec
WORKDIR /root/archerysec
ADD requirements.txt /root/archerysec
RUN pip install -r requirements.txt
COPY . /root/archerysec/

CMD ["python","manage.py","makemigrations","networkscanners"]

CMD ["python","manage.py","makemigrations","webscanners"]

CMD ["python","manage.py","makemigrations","projects"]

CMD ["python","manage.py","makemigrations","APIScan"]

CMD ["python","manage.py","migrate"]

EXPOSE 8000

WORKDIR /root/archerysec/

CMD ["python","manage.py","migrate"]
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
