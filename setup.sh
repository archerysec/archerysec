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
    export ARCHFLAGS='-arch x86_64'
    export LDFLAGS='-L/usr/local/opt/openssl/lib'
    export CFLAGS='-I/usr/local/opt/openssl/include'
    current_macos_version="$(sw_vers -productVersion | awk -F '.' '{print $1 "." $2}')"
    major=$(echo "$current_macos_version" | cut -d'.' -f1)
    minor=$(echo "$current_macos_version" | cut -d'.' -f2)
    is_installed=$(pkgutil --pkgs=com.apple.pkg.macOS_SDK_headers_for_macOS_${current_macos_version})
    if [ -z "$is_installed" ]; then
        if [ "$major" -ge "10" ] && [ "$minor" -lt "15" ]; then
            echo 'Please install command-line tools and macOS headers.'
            echo 'xcode-select --install'
            echo "sudo installer -pkg /Library/Developer/CommandLineTools/Packages/macOS_SDK_headers_for_macOS_${current_macos_version}.pkg -target /"
            exit 1
        else
            xcode-select -v
	    if ! [ $? -eq 0 ]; then
               echo 'Please install command-line tools'
               echo 'xcode-select --install'
               exit 1
	    fi
        fi
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

echo '[INSTALL] Installing Requirements'
pip install -r requirements.txt
echo 'Collect static files'
python manage.py collectstatic
echo '[INSTALL] Migrating Database'
python manage.py makemigrations
python manage.py migrate
echo '[INSTALL] Installation Complete'
