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
COPY . /root/archerysec/
EXPOSE 8000
RUN chmod +x install.sh
RUN ./install.sh
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
