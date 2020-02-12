#!/bin/bash

echo "[i] Subdomain Detect Script"
if [[ $# -eq 0 ]] ;
then
	echo "Usage: bash sub.sh bing.com"
	exit 1
else
	python Sublist3r/sublist3r.py -d $1 -o test/sublist3r_subdomains.txt
		echo "[+] Sublist3r Over"
	
	amass enum --passive -d $1 -o test/amass_subdomains.txt
		echo "[+] Amass Over"
	
	assetfinder -subs-only $1 |tee test/assetfinder_subdomains.txt
		echo "[+] assetfinder Over"
	
	python3 github-search/github-subdomains.py -d $1 -t c0d4eeda28652484cfdc1dcc82e501a15245c85c |tee test/github_subdomains.txt
		echo "[+] github-subdomains Over"
	
	curl -s "https://dns.bufferover.run/dns?q=."$1 | jq -r .FDNS_A[]|cut -d',' -f2|sort -u |tee test/FDNSA_subdomains.txt
		echo "[+] FDNS Over"
	
	python wordlist2subdomains.py $1 |./massdns/bin/massdns -r massdns/lists/resolvers.txt -t A -o S -w massdns/output.txt;cat massdns/output.txt | awk -F '. ' '{print $1}' | sort -u | uniq > test/wordlist_massdns_subdomains.txt
		echo "[+] wordlist2subdomains Over"
	
	curl -s "https://crt.sh/?q=%25."$1"&output=json"| jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u|grep -o "\w.*$1" > test/crt.sh_subdomains.txt
		echo "[+] Crt.sh Over"
	
	curl -s "http://web.archive.org/cdx/search/cdx?url=*."$1"/*&output=text&fl=original&collapse=urlkey" |sort| sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | uniq >>test/archive_subdomains.txt
		echo "[+] Web.Archive.org Over"

	curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1"|jq .subdomains|grep -o "\w.*$1" >>test/threatcrowd_subdomains.txt
		echo "[+] Threatcrowd.org Over"

	curl -s "https://api.hackertarget.com/hostsearch/?q=$1"|grep -o "\w.*$1" >>test/hackertarget_subdomains.txt
        echo "[+] Hackertarget.com Over"

	curl -s "https://certspotter.com/api/v0/certs?domain="$1 | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | sort -u | grep $1 >>test/certspotter_subdomains.txt
		echo "[+] Certspotter.com Over"

	curl -s  -X POST --data "url=$1&Submit1=Submit" https://suip.biz/?act=amass | grep $1 | cut -d ">" -f 2 | awk 'NF' | uniq >>test/Suip.biz_Amass_subdomains.txt
		echo "[+] Suip.biz Amass Over"

	curl -s  -X POST --data "url=$1&Submit1=Submit" https://suip.biz/?act=subfinder | grep $1 | cut -d ">" -f 2 | awk 'NF' | uniq >>test/Suip.biz_Subfinder_subdomains.txt
		echo "[+] Suip.biz Subfinder Over"
		
    curl -s -X POST --data "url=$1&only_resolved=1&Submit1=Submit" https://suip.biz/?act=findomain| grep $1 | cut -d ">" -f 2 | awk 'NF' |egrep -v "[[:space:]]"|uniq >>test/Suip.biz_Findomain_subdomains.txt  
	    echo "[+] Suip.biz Findomain Over"
	
	cat test/*_subdomains.txt | uniq | sort -u > test/subdomains_$1.log
	cat test/$1_subdomains.log|httprobe -t 15000 -c 50|cut -d "/" -f3|sort -u > test/alive_$1.log
	
	echo "Detect Subdomain $(wc -l test/subdomains_$1.log|awk '{ print $1 }' )" "=> ${1}"
	echo "Detect Alive Subdomain $(wc -l test/alive_$1.log|awk '{ print $1 }' )" "=> ${1}"
	
	
fi
