#Ubuntu base OS
FROM ubuntu:20.04
# Labels and Credits
LABEL \
    name="ArcherySec" \
    author="Anand Tiwari <anandtiwarics@gmail.com>" \
    maintainer="Anand Tiwari <anandtiwarics@gmail.com>" \
    description="Archery is an opensource vulnerability assessment and management tool which helps developers and pentesters to perform scans and manage vulnerabilities. Archery uses popular opensource tools to perform comprehensive scanning for web application and network. It also performs web application dynamic authenticated scanning and covers the whole applications by using selenium. The developers can also utilize the tool for implementation of their DevOps CI/CD environment."


ENV DJANGO_SETTINGS_MODULE="archerysecurity.settings.base" \
    DJANGO_WSGI_MODULE="archerysecurity.wsgi"

# Update & Upgrade Ubuntu. Install packages
RUN \
    DEBIAN_FRONTEND=noninteractive apt update -y && DEBIAN_FRONTEND=noninteractive apt install -y  --no-install-recommends \
    build-essential \
    sox ffmpeg libcairo2 libcairo2-dev \
    texlive-full \
    make \
    default-jre \
    wget \
    curl \
    unzip \
    git \
    python3.9 \
    python3-dev \
    python3-pip \
    virtualenv \
    gunicorn \
    postgresql \
    python3-psycopg2 \
    postgresql-server-dev-all \
    libpq-dev

# Set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8'

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

RUN virtualenv -p python /home/archerysec/app/venv

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
RUN . venv/bin/activate \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip install manimlib manimce

# Cleanup
RUN \
    apt remove -y \
        libssl-dev \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

RUN . venv/bin/activate && python -m pip install git+https://github.com/archerysec/openvas_lib.git && python /home/archerysec/app/manage.py collectstatic --noinput

# Exposing port.
EXPOSE 8000

# UP & RUN application.
CMD ["/usr/local/bin/init.sh"]
