#! /bin/bash

if [ ! $# == 1 ]; then
	echo "Usage: $0 path-of-ssl_log-files"
	exit
fi

#need quotes for $1 in case that the path contains spaces
if [ ! -d "$1" ]; then
	echo "$1 is not a folder"
	exit
fi

cd "$1"

if [ ! -f "maliciousDomains.txt" ]; then
	touch maliciousDomains.txt
fi

if [ ! -f "maliciousIPs.txt" ]; then
	touch maliciousIPs.txt
fi

if [ ! -f "nomalDomains.txt" ]; then
	touch nomalDomains.txt
fi

if [ ! -f "nomalIPs.txt" ]; then
	touch nomalIPs.txt
fi

for file in `find . -maxdepth 3 -type f -name '*.ssl.log'`
do
	echo "analyze $file"
	
	#extract domain name,if empty, extract IP
	servername=`bro-cut server_name < $file`
	if [ $servername = '-' ]; then
		serverIP=`bro-cut id.resp_h < $file`
		
		varMal=`grep "$serverIP" maliciousIPs.txt`
		varNom=`grep "$serverIP" nomalIPs.txt`
		
		if [ -n "$varMal" ]; then
			# the IP is alreadly labelled as malicious
			malicious_count=10000
		elif [ -n "$varNom" ]; then
			# the IP is alreadly labelled as normal
			malicious_count=-1
		else
			#a new IP
			malicious_count=`curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$serverIP --header 'x-apikey: your-key'| jq '.data.attributes.last_analysis_stats.malicious'`
		fi
			
		#calling virustotal API--return recognition result--parsing data using jq
		#For authenticating with the API you must include the x-apikey header with your personal API key in all your requests. Your API key can be found in your VirusTotal account user menu.
		#malicious_count=`curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$serverIP --header 'x-apikey: <your API key>'| jq '.data.attributes.last_analysis_stats.malicious'`
		
		
		#if more than 3 engines identify the IP address as malicious, the TLS flow is considered as malicious, and we move its data (include pcap, joy and bro information) to the specified folder.
		if [ "$malicious_count" == "null" ]; then 
			malicious_count=0
		fi
		
		if [ $malicious_count -ge 3 ]; then
			echo "$serverIP is marked as malicious by $malicious_count engines "
			if [ $malicious_count -ne 10000 ]; then 
				echo "$serverIP">>maliciousIPs.txt
			fi
			#obtain the absolute path of the ssl.log file
			f_pwd=`readlink -f "$file"`
			#file_path=${f_pwd%.ssl.log}
			#obtain the folder path
			file_path=${f_pwd%/*}
			#mv $file_path.pcap /home/zhou/MaliciousAttackTrafficCollectionAndAnalysis/malware-tls-flow
			cp -r -f "$file_path" /mnt/d/data/malicious-tls-flows/
		elif [ $malicious_count -ge 0 ]; then
			echo "$serverIP is not malicious. we write it to the nomalIPs.txt."
			echo "$serverIP">>nomalIPs.txt
		else	
			echo "$serverIP is not malicious. It is already in the nomalIPs.txt."
		fi
	else
		echo "Domain is $servername"
		#malicious_count=`curl --request GET --url https://www.virustotal.com/api/v3/domains/$servername --header 'x-apikey: <your API key>' | jq '.data.attributes.last_analysis_stats.malicious'`
		varMal=`grep "$servername" maliciousDomains.txt`
		varNom=`grep "$servername" nomalDomains.txt`
		
		if [ -n "$varMal" ]; then
			# the domain is alreadly labelled as malicious
			malicious_count=10000
		elif [ -n "$varNom" ]; then
			# the domain is alreadly labelled as normal
			malicious_count=-1
		else
			#a new domain
			malicious_count=`curl --request GET --url https://www.virustotal.com/api/v3/domains/$servername --header 'x-apikey: your-key' | jq '.data.attributes.last_analysis_stats.malicious'`
		fi
		
		#echo "malicious_count is $malicious_count."
		if [ "$malicious_count" == "null" ]; then 
			malicious_count=0
		fi
		
		if [ $malicious_count -ge 3 ]; then
			echo "$servername is marked as malicious by $malicious_count engines"
			if [ $malicious_count -ne 10000 ]; then 
				echo "$servername">>maliciousDomains.txt
			fi
			#f_pwd=`echo "$file"`
			#obtain the absolute path of the ssl.log file
			f_pwd=`readlink -f "$file"`
			#obtain the folder path
			file_path=${f_pwd%/*}
			#echo "$file_path"
			#file_path=${f_pwd%.ssl.log}
			#mv $file_path.pcap /home/zhou/MaliciousAttackTrafficCollectionAndAnalysis/malware-tls-flow
			cp -r -f "$file_path" /mnt/d/data/malicious-tls-flows/
		elif [ $malicious_count -ge 0 ]; then
			echo "$servername is not malicious. we write it to the nomalDomains.txt."
			echo "$servername">>nomalDomains.txt
		else	
			echo "$servername is not malicious. It is already in the nomalDomains.txt."
		fi
	fi
done

echo "We have finished the identificaion of malicious TLS flows by Virustotal."
