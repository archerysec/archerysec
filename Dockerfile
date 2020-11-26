#Ubuntu base OS
FROM ubuntu:18.04
LABEL MAINTAINER="Anand Tiwari"

ENV DJANGO_SETTINGS_MODULE="archerysecurity.settings.base" \
    DJANGO_WSGI_MODULE="archerysecurity.wsgi"

# Update & Upgrade Ubuntu. Install packages
RUN \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install --quiet --yes --fix-missing \
    make \
    default-jre \
    postgresql-client-10 \
    sslscan \
    nikto \
    nmap \
    wget \
    curl \
    unzip \
    git \
    python3-pip \
    virtualenv \
    gunicorn \
    postgresql \
    python-psycopg2 \
    postgresql-server-dev-all \
    python3-dev \
    && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get autoremove --purge -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create archerysec user and group
RUN groupadd -r archerysec && useradd -r -m -g archerysec archerysec

# Include init script
ADD ./docker-files/init.sh /usr/local/bin/init.sh

RUN chmod +x /usr/local/bin/init.sh

# Set user to archerysec to execute rest of commands
USER archerysec

# Create archerysec folder.
RUN mkdir /home/archerysec/app

# Set archerysec as a work directory.
WORKDIR /home/archerysec/app

RUN virtualenv -p python3 /home/archerysec/app/venv

# Copy all file to archerysec folder.
COPY . .

RUN mkdir nikto_result

RUN wget https://github.com/zaproxy/zaproxy/releases/download/2.7.0/ZAP_2.7.0_Linux.tar.gz

RUN tar -xvzf ZAP_2.7.0_Linux.tar.gz

RUN mkdir zap

RUN cp -r ZAP_2.7.0/* /home/archerysec/app/zap

COPY zap_config/policies /home/archerysec/app/zap

COPY zap_config/ascanrulesBeta-beta-24.zap /home/archerysec/app/zap/plugin/ascanrulesBeta-beta-24.zap

RUN rm -rf ZAP_2.7.0_Linux.tar.gz && \
    rm -rf ZAP_2.7.0

# Install requirements
RUN . venv/bin/activate && pip3 install --no-cache-dir -r requirements.txt && \
    rm -rf /home/archerysec/.cache

RUN . venv/bin/activate && python3 /home/archerysec/app/manage.py collectstatic --noinput

# Exposing port.
EXPOSE 8000

# UP & RUN application.
CMD ["/usr/local/bin/init.sh"]
