@echo off
title xxwfufu OSINT Tool - Installation des dependances
color 0A

echo.
echo ====================================================
echo       xxwfufu OSINT Tool - Installation
echo ====================================================
echo.

echo [+] Verification de Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python n'est pas installe ou pas dans le PATH
    echo [!] Veuillez installer Python depuis https://python.org
    pause
    exit /b 1
)

echo [+] Python detecte !
python --version

echo.
echo [+] Mise a jour de pip...
python -m pip install --upgrade pip

echo.
echo [+] Installation des dependances principales...

REM Dependances pour les requetes HTTP
echo [+] Installation de requests...
pip install requests

REM Dependances pour l'analyse d'images
echo [+] Installation de Pillow...
pip install Pillow

REM Dependances pour DNS
echo [+] Installation de dnspython...
pip install dnspython

REM Dependances pour WHOIS
echo [+] Installation de python-whois...
pip install python-whois

REM Dependances pour l'analyse de numeros de telephone
echo [+] Installation de phonenumbers...
pip install phonenumbers

REM Dependances pour Shodan (optionnel)
echo [+] Installation de shodan...
pip install shodan

REM Dependances supplementaires
echo [+] Installation de colorama (couleurs Windows)...
pip install colorama

echo [+] Installation de beautifulsoup4...
pip install beautifulsoup4

echo [+] Installation de lxml...
pip install lxml

echo.
echo ====================================================
echo [+] Installation terminee avec succes !
echo [+] Vous pouvez maintenant lancer: python xxwfufu_osint.py
echo ====================================================
echo.

pause