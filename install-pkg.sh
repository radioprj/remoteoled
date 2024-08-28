#!/bin/bash

dis=`lsb_release -i|cut -d: -f2 |tr -d '[:space:]'`
ver=`lsb_release -r|cut -d: -f2 |tr -d '[:space:]'`


if [ $dis == "Raspbian" ] || [ $dis == "Debian" ]; then

   if [ $ver == "11" ]; then

    echo "Instalacja pakietów dla Remote OLED na bazie Debian 11"
    echo ""
    sudo apt-get update
    sudo apt install -y python3 python3-pip python3-dev python3-numpy python3-watchdog python3-requests
    sudo python3 -m pip install --upgrade setuptools
    sudo python3 -m pip install psutil
    sudo python3 -m pip install unidecode
    echo ""
    echo "Kopiowanie remoteoled.service do /lib/systemd/system/"
    sudo cp /opt/fmpoland/remoteoled/remoteoled.service /lib/systemd/system/
    echo ""
    echo "Instalacja zakonczona ...."
    echo ""
   fi

   if [ $ver == "12" ]; then

    echo "Instalacja pakietów dla Remote OLED na bazie Debian 12"
    echo ""
    sudo apt-get update
    sudo apt install -y python3 python3-pip python3-dev python3-numpy python3-watchdog python3-requests
    sudo python3 -m pip install --upgrade setuptools --break-system-packages
    sudo python3 -m pip install psutil --break-system-packages
    sudo python3 -m pip install unidecode --break-system-packages
    echo ""
    echo "Kopiowanie remoteoled.service do /lib/systemd/system/"
    sudo cp /opt/fmpoland/remoteoled/remoteoled.service /lib/systemd/system/
    echo ""
    echo "Instalacja zakonczona ...."
    echo ""

   fi

else

  echo ""
  echo " UWAGA - proces instalacji bibliotek systemowych przerwany"
  echo " Uzywasz dystrybucji systemu na bazie: $dis $ver"
  echo " Instalacja bibliotek przygotowana dla dystrubucji na bazie Debian v11 lub v12"
  echo ""

fi
