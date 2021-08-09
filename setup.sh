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

echo '[INSTALL] openvas_lib from github'
python3 -m pip install git+https://github.com/archerysec/openvas_lib.git
echo '[INSTALL] Installing Requirements'
pip install --no-cache-dir --use-deprecated=legacy-resolver -r requirements.txt
echo 'Collect static files'
python manage.py collectstatic --noinput
echo '[INSTALL] Migrating Database'
python manage.py makemigrations
python manage.py migrate
echo '[INSTALL] Installation Complete'
echo '================================================================='
echo 'User Creating'
source venv/bin/activate
echo 'Apply Fixtures'
python manage.py loaddata fixtures/default_user_roles.json
python manage.py loaddata fixtures/default_organization.json
echo "from user_management.models import UserProfile; UserProfile.objects.create_superuser(name='${NAME}', email='${EMAIL}', password='${PASSWORD}', role=1, organization=1)" | python manage.py shell
echo '================================================================='
echo 'User Created'
echo 'User Name :' ${NAME}
echo 'User Email': ${EMAIL}
echo 'Role : Admin'
echo 'Done !'