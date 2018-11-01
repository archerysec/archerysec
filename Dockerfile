#Ubuntu base OS
FROM ubuntu:18.04
LABEL MAINTAINER="Anand Tiwari"  

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

#Exposing port.
EXPOSE 8000

#Running installation file.
RUN chmod +x install.sh && ./install.sh

# UP & RUN application.
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
