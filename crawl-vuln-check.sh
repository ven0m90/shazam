#!/bin/bash

#crawl-vuln-check

host=$1

#check

if [ "$1" == "" ]
then


    exit
fi

#check

for domain in $(cat $host);
do


mkdir -p  shazam-output  shazam-output/$domain shazam-output/$domain/urls  shazam-output/$domain/gf shazam-output/$domain/target_wordlist
chmod +rwx shazam-output/

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] crawl-vuln-check  Started  $domain \033[m" | notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' | notify -silent -bulk
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"


sleep 1
echo -e "\033[33m[+] httpx  --> $domain  \033[m"
echo "$domain" | httpx -silent | anew  shazam-output/$domain/httpx.txt
sleep 1

echo -e "\033[31m[+] Collecting URLS --> waybackurls,gau,katana \033[m"
echo -e "\033[36m[+] waymore Started  --> \033[m"
cat shazam-output/$domain/httpx.txt | waymore -mode U  --no-subs -oU shazam-output/$domain/urls/tmp.txt

echo -e "\033[36m[+] katana active Started  --> \033[m"
katana -silent -c 200  -list shazam-output/$domain/httpx.txt -cs shazam-output/$domain/httpx.txt  -o shazam-output/$domain/urls/tmp.txt


cat shazam-output/$domain/urls/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpep|\.jpeg|\.css|\.ico|\jpg" | sed 's/:80//g;s/:443//g' | sort -u >> shazam-output/$domain/urls/tmp_url.txt
rm shazam-output/$domain/urls/tmp.txt
sleep 1
#____________________________________________________________________________________________________________________________________________________________________________________________


sleep 2
echo -e "\033[36m[+] FFUF Started On URLS --> \033[m"
ffuf -t 100 -c -u "FUZZ" -w shazam-output/$domain/urls/tmp_url.txt -of csv -o shazam-output/$domain/urls/valid-tmp.txt

cat shazam-output/$domain/urls/valid-tmp.txt | grep http | awk -F "," '{print $1}'  >>  shazam-output/$domain/urls/valid_urls.txt
rm shazam-output/$domain/urls/valid-tmp.txt
#____________________________________________________________________________________________________________________________________________________________________________________________

echo -e "\033[36m[+] Generating Target Based Wordlist --> \033[m"
cat shazam-output/$domain/urls/tmp_url.txt | unfurl -unique paths > shazam-output/$domain/target_wordlist/paths.txt
cat shazam-output/$domain/urls/tmp_url.txt | unfurl -unique keys > shazam-output/$domain/target_wordlist/param.txt
#____________________________________________________________________________________________________________________________________________________________________________________________
rm shazam-output/$domain/urls/tmp_url.txt
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

echo -e "\033[33m[+] Paramspider  Started... $domain  \033[m"
sleep 2
cat  shazam-output/$domain/httpx.txt  |unfurl domains | anew shazam-output/$domain/urls/$domain-paramspider.txt
#paramspider
cd  shazam-output/$domain/
paramspider -l urls/$domain-paramspider.txt
cat results/*.txt | anew urls/valid_urls.txt
cd ../../

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

#gf
echo -e "\033[36m[+] Gf Patterns Started on Valid URLS --> \033[m"
gf xss shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/xss.txt
gf ssrf shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/ssrf.txt
gf sqli shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/sql.txt
gf lfi shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/lfi.txt
gf ssti shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/ssti.txt
gf redirect shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/redirect.txt
gf idor shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/idor.txt
gf ip shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/ip.txt
gf rce shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/rce.txt
gf s3-buckets shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/s3-buckets.txt
gf upload-fields shazam-output/$domain/urls/valid_urls.txt |anew shazam-output/$domain/gf/upload-fields.txt





#xss-url-filter
echo -e "\033[36m[+] Xss url filter --> \033[m"

cat shazam-output/$domain/urls/valid_urls.txt | uro| qsreplace FUZZ| grep -aiE '^http' | grep -aiE '\?' |grep FUZZ | grep -iavE 'pdf|txt|\?l=FUZZ$|\?contry=FUZZ$|\?q=FUZZ$|is/image' | anew  shazam-output/$domain/urls/xss-url.txt
cat shazam-output/$domain/urls/valid_urls.txt| uro| grep -viE '\.png|\.jpg|\.jpeg|\.css|\.js|\.svg|\.gif' | grep -iE 'feedback|support' | qsreplace FUZZ | sort -u | anew  shazam-output/$domain/urls/xss-url.txt
cat shazam-output/$domain/urls/valid_urls.txt| uro|  grep -viE '\.png|\.jpg|\.jpeg|\.css|\.js|\.svg|\.gif' | grep -iE 'login|register|auth|sign|account' | qsreplace FUZZ | sort -u | anew  shazam-output/$domain/urls/xss-url.txt


echo -e "\033[31m[+] Js Finding.... --> \033[m"

echo -e "\033[36m[+] passive Js Crawling Started  --> \033[m"
cat shazam-output/$domain/urls/valid_urls.txt |grep "\.js$"|  anew  shazam-output/$domain/urls/js-tmp.txt

echo -e "\033[33m[+] katana active Js Crawling Started  --> \033[m"
cat shazam-output/$domain/httpx.txt | katana  -silent  -jc  -c 100 -kf all |grep "\.js$" |anew shazam-output/$domain/urls/js-tmp.txt


#echo -e "\033[36m[+] httpx checking live js Started  --> \033[m"
#cat shazam-output/$domain/urls/js-tmp.txt | httpx -mc 200 -silent -c 50 | anew shazam-output/$domain/urls/live-js.txt
#cat shazam-output/$domain/urls/valid_urls.txt | httpx -mc 200 -silent -c 50 | anew shazam-output/$domain/urls/live-js.txt

echo -e "\033[36m[+] ffuf checking live js Started  --> \033[m"
ffuf -t 100 -c -mc 200 -u "FUZZ" -w shazam-output/$domain/urls/js-tmp.txt -of csv -o shazam-output/$domain/urls/live-js-tmp.txt

cat shazam-output/$domain/urls/live-js-tmp.txt | grep http | awk -F "," '{print $1}'  >>  shazam-output/$domain/urls/live-js.txt
rm shazam-output/$domain/urls/live-js-tmp.txt

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

#js-download
mkdir -p shazam-output/$domain/urls/js-download

echo -e "\033[33m[+] Downloading js files   --> $domain \033[m"
cat  shazam-output/$domain/urls/live-js.txt| xargs -I{} wget -c "{}"  -P shazam-output/$domain/urls/js-download/

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"


#scret-find
mkdir -p  shazam-output/$domain/js-secret
echo -e "\033[31m[+] secret checking live js Started  --> \033[m"

cat   shazam-output/$domain/urls/live-js.txt | nipejs -s |  anew   shazam-output/$domain/js-secret/nipejs-secret
#cat   shazam-output/$domain/urls/live-js.txt | while read url; do python3 ~/tools/secretfinder/SecretFinder.py  -i $url -o cli;done | anew   shazam-output/$domain/js-secret/secretfinder
#cat   shazam-output/$domain/urls/live-js.txt | mantra -s | anew   shazam-output/$domain/js-secret/mantra-secret

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

#gf-nipesec

echo -e "\033[36m[+] GF Patterns Started on nipesec --> \033[m"

cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf xss |anew shazam-output/$domain/gf/xss.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf ssrf |anew shazam-output/$domain/gf/ssrf.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf sqli |anew shazam-output/$domain/gf/sql.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf lfi |anew shazam-output/$domain/gf/lfi.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf ssti |anew shazam-output/$domain/gf/ssti.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf redirect |anew shazam-output/$domain/gf/redirect.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf idor |anew shazam-output/$domain/gf/idor.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf ip |anew shazam-output/$domain/gf/ip.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf rce |anew shazam-output/$domain/gf/rce.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf s3-buckets |anew shazam-output/$domain/gf/s3-buckets.txt
cat shazam-output/$domain/js-secret/nipejs-secret  | grep http | sort -u|grep -o -E 'https?://[^"]+' |gf upload-fields |anew shazam-output/$domain/gf/upload-fields.txt





#echo -e "\033[31m[+] nuclei js checking secret Started  --> \033[m"
#nuclei -c 50 -l shazam-output/$domain/urls/live-js.txt -tags js-analyse,exposure -o shazam-output/$domain/js-secret/nulcei-secret


#____________________________________________________________________________________________________________________________________________________________________________________________


echo -e "\033[31m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] crawl-vuln-check  Done!  $domain \033[m" |notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' |notify -silent -bulk
echo -e "\033[32m[+] Output Save in -->  shazam-output/$domain/ \033[m"

done
