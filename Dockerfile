#Ubuntu base OS
FROM ubuntu:18.04
MAINTAINER Anand Tiwari

#Create archerysec folder.
RUN mkdir archerysec

#Set archerysec as a work directory.
WORKDIR archerysec

#Adding requirements file.
ADD requirements.txt archerysec

# Update & Upgrade Ubuntu
RUN apt-get update && apt-get -y upgrade

#Install dependency tools.
RUN apt-get install --quiet --yes --fix-missing \
        make \
        sslscan \
        nikto \
        nmap \
        python \
        wget \
        curl \
        unzip \
        git \
        python-pip

#Copy all file to archerysec folder.
COPY . /archerysec

#Exposing port.
EXPOSE 8000

#Given permission to install.sh file.
RUN chmod +x install.sh

#Running installation file.
RUN ./install.sh

# UP & RUN application.
CMD ["python","manage.py","runserver","0.0.0.0:8000"]
