#Ubuntu base OS
FROM ubuntu:18.04
LABEL MAINTAINER="Anand Tiwari"

ENV DJANGO_SETTINGS_MODULE=archerysecurity.settings.production

#Create archerysec folder.
RUN mkdir /archerysec

#Set archerysec as a work directory.
WORKDIR /archerysec

# Update & Upgrade Ubuntu. Install packages
RUN \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get --quiet -y upgrade && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install --quiet --yes --fix-missing \
    make \
    postgresql-client-10 \
    sslscan \
    nikto \
    nmap \
    python \
    wget \
    curl \
    unzip \
    git \
    python-pip \
    && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

#Copy all file to archerysec folder.
COPY . /archerysec

# Install requirements
RUN pip install -r requirements.txt && \
    rm -rf /root/.cache

#Exposing port.
EXPOSE 8000

# Include init script
ADD ./docker-files/init.sh /sbin/init.sh

# UP & RUN application.
CMD ["/sbin/init.sh"]
