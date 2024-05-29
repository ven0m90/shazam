#!/bin/bash

#Shodanx Ip Finding

host=$1

#check

if [ "$1" == "" ]
then


    exit
fi

#check

for domain in $(cat $host);
do


mkdir -p  shazam-output  shazam-output/$domain
chmod +rwx shazam-output/

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] Shodanx Ip Finding   Started  $domain \033[m" | notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' | notify -silent -bulk
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"


mkdir -p shazam-output/$domain/shodan

echo -e "\033[36m[+] Shodanx Ip Finding  Started... $domain --> \033[m"
shodanx domain -d $domain  -to 10  -ra -o shazam-output/$domain/shodan/ips.txt

echo -e "\033[36m[+] Dnsx domain checking... $domain --> \033[m"
cat  shazam-output/$domain/shodan/ips.txt| dnsx  -silent  -recon | anew shazam-output/$domain/shodan/ips-dnsx.txt 

#grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' |httpx -silent -title -td -sc -ip -server|anew ips-indeed-httpx-tech.txt
echo -e "\033[36m[+]Port Scannig Started...ips.txt ->\033[m"  
naabu -c 100  -silent -list   shazam-output/$domain/shodan/ips.txt  -o shazam-output/$domain/shodan/ips-naabu.txt 
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"


#httpx

echo -e "\033[36m[+]httpx -Started... ->\033[m"  
cat  shazam-output/$domain/shodan/ips-naabu.txt  | sort -u| httpx -silent -t 100 | anew   shazam-output/$domain/shodan/ips-httpx.txt   
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

echo -e "\033[36m[+]Screenshot Started -->\033[m"  
cat  shazam-output/$domain/shodan/ips-httpx.txt  | aquatone -out  shazam-output/$domain/shodan/screenshot -scan-timeout 200 -screenshot-timeout 60000 
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"


echo -e "\033[31m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] Shodanx Ip Finding   Done!  $domain \033[m" |notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' |notify -silent -bulk
echo -e "\033[32m[+] Output Save in -->  shazam-output/shazam-output/$domain/ \033[m"

done
