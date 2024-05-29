#Subdomain Enumeration

host=$1

#check

if [ "$1" == "" ]
then
    echo "Usage: $0 domains.txt  "
    echo "Ex: $0 dell.txt "

    exit
fi
    
#check

for domain in $(cat $host);
do


mkdir -p  shazam-output  shazam-output/$domain  shazam-output/$domain/tmp  shazam-output/$domain/vulnerabilities  shazam-output/$domain/vulnerabilities/takeovers 
chmod +rwx shazam-output/

echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+]Subdomain Enumeration  $domain \033[m" | notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' | notify -silent -bulk
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"



#____________________________________________________________________________________________________________________________________________________________________________________________


echo -e "\033[36m[+]Subdomain Passive Enumeration-Started... --> $domain\033[m" 
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew shazam-output/$domain/tmp/assetfinder.txt 
assetfinder -subs-only $domain  | anew shazam-output/$domain/tmp/assetfinder.txt 
findomain -t $domain -q |   anew shazam-output/$domain/tmp/findomain.txt
subfinder -all -d  $domain  -silent  -o shazam-output/$domain/tmp/subfinder.txt
shodanx subdomain -d $domain  -to 5  -ra -o shazam-output/$domain/tmp/subdomains-shodanx.txt
amass enum -passive -norecursive  -d $domain |anew  shazam-output/$domain/tmp/subdomains-shodanx.txt
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
sleep 2
#____________________________________________________________________________________________________________________________________________________________________________________________

##subdomain-bruteforcing..
echo -e "\033[36m[+]Subdomain Bruteforcing-Started... -> $domain\033[m" 
shuffledns -mode bruteforce -silent -d $domain -w  ~/wordlist/dns/n0kovo_subdomains_tiny.txt -r ~/wordlist/resolvers.txt -o shazam-output/$domain/tmp/shuffledns.txt
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
#____________________________________________________________________________________________________________________________________________________________________________________________


echo -e "\033[36m[+]Permutation.list.Making-Started... -> $domain\033[m" 
rm /tmp/permutation.txt
cat shazam-output/$domain/tmp/*.txt |sort -u | haklistgen | anew /tmp/permutation.txt
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

echo -e "\033[36m[+]Subdomain Resolving-Started... -> $domain\033[m" 
shuffledns -mode  resolve -silent -d $domain -list /tmp/permutation.txt -r ~/wordlist/resolvers.txt -o shazam-output/$domain/tmp/resolved.txt
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

cat shazam-output/$domain/tmp/*.txt |sort -u | anew shazam-output/$domain/allsub.txt
rm /tmp/permutation.txt

#portscannig
echo -e "\033[36m[+]Port Scannig Started... ->\033[m" allsub.txt  
naabu  -c 50 -silent -list  shazam-output/$domain/allsub.txt  -o shazam-output/$domain/allsub-naabu.txt 
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
sleep 2
#httpx

echo -e "\033[36m[+]httpx -Started... ->\033[m"  
cat shazam-output/$domain/allsub-naabu.txt  | sort -u| httpx -silent -t 50 | anew  shazam-output/$domain/httpx.txt    
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"
sleep 1

echo -e "\033[36m[+]httpx -title -td -sc Started... ->\033[m"   
cat  shazam-output/$domain/httpx.txt   | sort -u| httpx -silent -title -td -sc -server -t 50| anew shazam-output/$domain/httpx-tech-output.txt 
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"


#screenshotting-subdomain
echo -e "\033[36m[+]Screenshot Started -->\033[m"  
cat shazam-output/$domain/httpx.txt    | aquatone -out shazam-output/$domain/subdomains-screenshot -scan-timeout 200 -screenshot-timeout 60000 
echo -e "\033[32m_____________________________________________________________________________________________________________________________________\033[m"

#sub-takeover
echo -e "\033[36m[+]subdominator takover Checking.. Started... ->\033[m"  
subdominator -l shazam-output/$domain/allsub.txt  --validate  -o shazam-output/$domain/vulnerabilities/takeovers/takeovers-found.txt 
#subzy run  --targets shazam-output/$domain/allsub.txt  --vuln  --hide_fails --output  shazam-output/$domain/vulnerabilities/takeovers/subzy.txt 

rm custom_fingerprints.json  fingerprints.json


echo -e "\033[31m_____________________________________________________________________________________________________________________________________\033[m"
echo -e "\033[33m[+] Subdomain Enumeration Done!  $domain \033[m" |notify -silent -bulk
date    '+DATE: %m/%d/%y%nTIME:%r' |notify -silent -bulk
echo -e "\033[32m[+] Output Save in -->  shazam-output/$domain/ \033[m" 

done
