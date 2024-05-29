#Ubuntu base OS
FROM ubuntu:22.04

# Labels and Credits
LABEL \
    name="ArcherySec" \
    author="Anand Tiwari <anandtiwarics@gmail.com>" \
    maintainer="Anand Tiwari <anandtiwarics@gmail.com>" \
    description="Archery is an opensource vulnerability assessment and management tool which helps developers and pentesters to perform scans and manage vulnerabilities. Archery uses popular opensource tools to perform comprehensive scanning for web application and network. It also performs web application dynamic authenticated scanning and covers the whole applications by using selenium. The developers can also utilize the tool for implementation of their DevOps CI/CD environment."


ENV DJANGO_SETTINGS_MODULE="archerysecurity.settings.base" \
    DJANGO_WSGI_MODULE="archerysecurity.wsgi" \
    DEBIAN_FRONTEND=noninteractive

# Update & Upgrade Ubuntu. Install packages
RUN \
    apt update -y && apt install -y  --no-install-recommends \
    build-essential \
    default-jre \
    wget \
    curl \
    unzip \
    git \
    python3 \
    python3-dev \
    python3-pip \
    pkg-config \
    virtualenv \
    gunicorn \
    postgresql \
    python3-psycopg2 \
    postgresql-server-dev-all \
    libpq-dev \
    python-is-python3 \
    openssh-client \
    python3.10-venv

# Set locales
RUN locale-gen en_US.UTF-8
ENV LANG='en_US.UTF-8' LANGUAGE='en_US:en' LC_ALL='en_US.UTF-8' \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    POETRY_VERSION=1.6.1 \
    POETRY_VIRTUALENVS_CREATE=false

# Create archerysec user and group
RUN groupadd -g 9901 archerysec 
RUN adduser archerysec --shell /bin/false -u 9901 --ingroup archerysec --gecos "" --disabled-password

# Install Poetry
RUN python3 -m pip install --upgrade --no-cache-dir pip && \
    python3 -m pip install --no-cache-dir poetry==$POETRY_VERSION

# Copy the dependency files to the container
COPY pyproject.toml poetry.lock ./

# Configure Poetry to not create virtual environments
RUN poetry config virtualenvs.create $POETRY_VIRTUALENVS_CREATE

# Install dependencies
RUN poetry install --only main --no-root --no-interaction --no-ansi

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

# Create archerysec folder.
RUN mkdir /home/archerysec/app

# Set archerysec as a work directory.
WORKDIR /home/archerysec/app

# Copy all file to archerysec folder.
COPY . .

# Include init script
ADD ./docker-files/init.sh /usr/local/bin/init.sh

RUN chmod +x /usr/local/bin/init.sh

RUN mkdir nikto_result

# Cleanup
RUN \
    apt remove -y \
        python3-dev \
        wget && \
    apt clean && \
    apt autoclean && \
    apt autoremove -y && \
    rm -rf /var/lib/apt/lists/* /tmp/* > /dev/null 2>&1

# Exposing port.
EXPOSE 8000

RUN chown -R archerysec:archerysec /home/archerysec/app
USER archerysec


# UP & RUN application.
CMD ["/usr/local/bin/init.sh"]
