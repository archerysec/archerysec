@echo off

where python >nul 2>&1 && (

  deactivate >nul 2>&1

  echo [INSTALL] Found Python3

  pip >nul 2>&1 && (

    echo [INSTALL] Found pip

    python -m pip install --no-cache-dir --upgrade pip

  ) || (

    echo [ERROR] pip is not available in PATH

    pause

    exit /b

  )



  if exist "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe" (

    echo [INSTALL] Found OpenSSL executable

  ) else (

   echo [ERROR] OpenSSL executable not found in [C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe]

   echo [INFO] Install OpenSSL - https://slproweb.com/download/Win64OpenSSL-1_1_1g.exe

   pause

   exit /b

  )



  echo [INSTALL] Using venv

  rmdir "venv" /q /s >nul 2>&1

  python -m venv ./venv

  .\venv\Scripts\activate

  python -m pip install --upgrade pip wheel



  set LIB=C:\Program Files\OpenSSL-Win64\lib;%LIB%

  set INCLUDE=C:\Program Files\OpenSSL-Win64\include;%INCLUDE%



  echo [INSTALL] Installing Requirements

  pip install --no-cache-dir -r requirements.txt
  
  echo [Static] Copy static files
   
  python manage.py collectstatic


  echo [INSTALL] Migrating Database

  python manage.py makemigrations

  python manage.py migrate

) || (

  echo [ERROR] python3 is not installed

)