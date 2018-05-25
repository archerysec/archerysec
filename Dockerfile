FROM python:2.7
RUN mkdir /root/archerysec
WORKDIR /root/archerysec
ADD requirements.txt /root/archerysec
RUN pip install -r requirements.txt
COPY . /root/archerysec/
EXPOSE 8000
RUN chmod +x docker_run.sh
RUN ./docker_run.sh
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
