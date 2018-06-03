FROM kalilinux/kali-linux-docker
RUN mkdir /root/archerysec
WORKDIR /root/archerysec
ADD requirements.txt /root/archerysec
RUN apt-get update && apt-get install -q -y --fix-missing \
        make \
        openjdk-8-jdk \
        zaproxy \
        sslscan \
        nikto \
        nmap \
        python \
        wget \
        curl \
        unzip \
        git \
        python-pip
WORKDIR /root/archerysec
RUN python manage.py process_tasks &
RUN pip install -r requirements.txt
COPY . /root/archerysec/
EXPOSE 8000
RUN chmod +x docker_run.sh
RUN ./docker_run.sh
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
