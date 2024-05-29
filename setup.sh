#!/bin/bash
# Python3 Check
unamestr=$(uname)
if ! [ -x "$(command -v python3)" ]; then
    echo '[ERROR] python3 is not installed.' >&2
    exit 1
fi

# Python3 Version Check
python_version="$(python3 --version 2>&1 | awk '{print $2}')"
py_major=$(echo "$python_version" | cut -d'.' -f1)
py_minor=$(echo "$python_version" | cut -d'.' -f2)
if [ "$py_major" -eq "3" ] && [ "$py_minor" -gt "9" ] && [ "$py_minor" -lt "12" ]; then
    echo "[INSTALL] Found Python ${python_version}"
else
    echo "[ERROR] ArcherySec require Python 3.10 - 3.11. You have Python version ${python_version} or python3 points to Python ${python_version}."
    exit 1
fi

# Function to check if a command exists
command_exists() {
  command -v "$1" &> /dev/null
}

# Function to check if a package is installed on Debian-based systems
check_debian_package() {
  dpkg -s "$1" &> /dev/null
}

# Function to check if a package is installed on Red Hat-based systems
check_redhat_package() {
  rpm -q "$1" &> /dev/null
}

# Function to check if a package is installed on macOS using Homebrew
check_brew_package() {
  brew list --versions "$1" &> /dev/null
}

# Check the OS and package manager
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  if command_exists dpkg; then
    # Debian-based system
    if check_debian_package libmagic1; then
      echo "libmagic1 is installed on Debian-based system."
    else
      echo "libmagic1 is not installed on Debian-based system."
      exit 1
    fi
  elif command_exists rpm; then
    # Red Hat-based system
    if check_redhat_package file; then
      echo "file (including libmagic) is installed on Red Hat-based system."
    else
      echo "file (including libmagic) is not installed on Red Hat-based system."
      exit 1
    fi
  else
    echo "Unsupported Linux package manager."
  fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
  if command_exists brew; then
    # macOS system with Homebrew
    if check_brew_package libmagic; then
      echo "libmagic is installed on macOS via Homebrew."
    else
      echo "libmagic is not installed on macOS via Homebrew."
      exit 1
    fi
  else
    echo "Homebrew is not installed on macOS."
  fi
else
  echo "Unsupported operating system."
fi

# Pip Check and Upgrade
python3 -m pip -V
if [ $? -eq 0 ]; then
    echo '[INSTALL] Found pip'
    if [[ $unamestr == 'Darwin' ]]; then
        python3 -m pip install --no-cache-dir --upgrade pip
    else
        python3 -m pip install --no-cache-dir --upgrade pip --user
    fi
else
    echo '[ERROR] python3-pip not installed'
    exit 1
fi


# macOS Specific Checks
if [[ $unamestr == 'Darwin' ]]; then
    # Check if xcode is installed
    xcode-select -v
    if ! [ $? -eq 0 ]; then
        echo 'Please install command-line tools'
        echo 'xcode-select --install'
        exit 1
    else
        echo '[INSTALL] Found Xcode'
	  fi    
fi


echo '[INSTALL] Installing Requirements'
python3 -m pip install --no-cache-dir wheel poetry==1.6.1
python3 -m poetry install --no-root --only main --no-interaction --no-ansi


echo "Checking Variables"
if [ -z "$NAME" ]
then
      echo "\$NAME is empty, Please Provide User Name. Ex NAME=user"
      exit 1
else
      echo "\$NAME Found"
fi

if [ -z "$EMAIL" ]
then
      echo "\$EMAIL is empty, Please Provide User Name. Ex EMAIL=user@user.com"
      exit 1
else
      echo "\$EMAIL Found"
fi

if [ -z "$PASSWORD" ]
then
      echo "\$PASSWORD is empty, Please Provide User Name. Ex PASSWORD=userpassword"
      exit 1
else
      echo "\$PASSWORD Found"
fi


echo '[INSTALL] Migrating Database'
python3 -m poetry run python manage.py makemigrations
python3 -m poetry run python manage.py migrate
echo '[INSTALL] Installation Complete'
echo '================================================================='
echo 'User Creating'
echo 'Apply Fixtures'
python3 -m poetry run python manage.py loaddata fixtures/default_user_roles.json
python3 -m poetry run python manage.py loaddata fixtures/default_organization.json
echo "from user_management.models import UserProfile; UserProfile.objects.create_superuser(name='${NAME}', email='${EMAIL}', password='${PASSWORD}', role=1, organization=1)" | python3 -m poetry run python manage.py shell
echo '================================================================='
echo 'User Created'
echo 'User Name :' ${NAME}
echo 'User Email': ${EMAIL}
echo 'Role : Admin'
echo 'Done !'
echo '[INSTALL] Installation Complete'