#----------------------------------------------
# Setup Environment
#----------------------------------------------

PATH =/usr/bin:/bin
umask 022
PDIR=${0%'basename $0'}

#Install python 3.5
sudo apt install python3.5

#Install Pip
apt install python-pip

#install mysqldb
sudo pip install MySQL-python

#install confiparser
sudo pip install ConfigParser

#install  python-dev libm
apt install python-dev libmysqlclient

# install dsnitch
