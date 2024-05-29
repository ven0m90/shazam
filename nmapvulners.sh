#!/bin/bash

#nmap-vulners cve scan

host=$1

#check

if [ "$1" == "" ]
then
    echo -e "\033[33m[+]Usage:\033[m sudo $0"

    exit
fi

if [ "$EUID" -ne 0 ]
  then 
    echo "Please use sudo" 
  exit
fi

#check

for domain in $(cat $host);
do


mkdir -p  nmap 
chmod +rwx nmap/

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+]nmap-vulners cve scan $domain \033[m" | notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' | notify -silent -bulk
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

echo -e "\033[36m[+]nmap vulners Scannig Started -top-ports 1000  --> $domain \033[m"
cat $domain |  sudo naabu -c 50 -top-ports 1000	  -silent  -nmap-cli "nmap --min-rate 10000 -Pn -T4 -D RND:5 -sVC -v  --script vulners.nse --script-args mincvss=5.0 -oX $domain-nmap.xml"

sudo mv $domain-nmap.xml  nmap/
sudo xsltproc  nmap/$domain-nmap.xml -o nmap/$domain-nmap.html



#xsltproc  



#___________________________________________________________________________________________________________________________________________________________________________________________




echo -e "\033[31m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] nmap-vulners cve scan Done!  $domain \033[m" |notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' |notify -silent -bulk

done
