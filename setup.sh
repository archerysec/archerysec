#!/bin/bash
unamestr=$(uname)
if ! [ -x "$(command -v python3)" ]; then
  echo '[ERROR] python3 is not installed.' >&2
  exit 1
fi
echo '[INSTALL] Found Python3'

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

echo '[INSTALL] Using python virtualenv'
rm -rf ./venv
python3 -m venv ./venv
if [ $? -eq 0 ]; then
    echo '[INSTALL] Activating virtualenv'
    source venv/bin/activate
    pip install --upgrade pip wheel
else
    echo '[ERROR] Failed to create virtualenv. Please install ArcherySec requirements mentioned in Documentation.'
    exit 1
fi
echo '[INSTALL] openvas_lib from github'
python3 -m pip install git+https://github.com/archerysec/openvas_lib.git
echo '[INSTALL] Installing Requirements'
pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt
echo 'Collect static files'
python manage.py collectstatic
echo '[INSTALL] Migrating Database'
python manage.py makemigrations
python manage.py migrate
echo '[INSTALL] Installation Complete'