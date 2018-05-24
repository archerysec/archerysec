FROM python:2.7
RUN mkdir /root/archerysec
WORKDIR /root/archerysec
ADD requirements.txt /root/archerysec
RUN pip install -r requirements.txt
COPY . /root/archerysec/

RUN ./run.sh

EXPOSE 8000

WORKDIR /root/archerysec/
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
