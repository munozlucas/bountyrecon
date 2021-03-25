#!/bin/bash

# todo poder mandar varios dominios
domain=$1
mkdir -p $domain $domain/sources $domain/scans $domain/scans/nuclei $domain/scans/gau $domain/scans/gf

domain_enum(){
	subfinder -d $domain -o $domain/sources/subfinder.txt
	assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
	amass enum -d $domain -o $domain/sources/amass.txt

	cat $domain/sources/*.txt > $domain/sources/all.txt
}
domain_enum

alive(){
	cat $domain/sources/all.txt | httpx -threads 200 -o $domain/scans/alive.txt
}
alive

nuclei_scanner(){
	cat $domain/scans/httpx.txt | nuclei -i /nuclei-templates/cves/ -c 50 -o $domain/scans/nuclei/cves.txt
	cat $domain/scans/httpx.txt | nuclei -i /nuclei-templates/vulnerabilities/ -c 50 -o $domain/scans/nuclei/vulnerabilities.txt
	cat $domain/scans/httpx.txt | nuclei -i /nuclei-templates/files/ -c 50 -o $domain/scans/nuclei/files.txt
	cat $domain/scans/httpx.txt | nuclei -i /nuclei-templates/payloads/ -c 50 -o $domain/scans/nuclei/payloads.txt
	cat $domain/scans/httpx.txt | nuclei -i /nuclei-templates/generic-detections/ -c 50 -o $domain/scans/nuclei/generic.txt

}
nuclei_scanner

gau_recon(){
	cat $domain/sources/all.txt | gau | tee $domain/scans/gau/tmp.txt
//aca abajo agregar el bug bounty tip de eliminar todos los duplicados ver punto 5 arriba
	cat $domain/scans/gau/tmp.txt | egrep -v ".(woff|ttf|svg|eot|png|jpeg|jpg|css|ico)" | sed 's/:80//g;s/:443//g' | sort -u > $domain/scans/gau/gau.txt
	rm $domain/scans/gau/tmp.txt
}
gau_recon

valid_urls(){
	ffuf -c -u "FUZZ" -w $domain/scans/gau/gau.txt -o $domain/scans/gau/valid-temp.txt
	cat $domain/scans/gau/valid-temp.txt | grep http | awk -F "," '{print $1}' >> $domain/scans/gau/valid.txt
	$domain/scans/gau/valid-temp.txt
}
valid_urls

gf_recon(){
	gf xss $domain/scans/gau/valid.txt | tee $domain/scans/gf/xss.txt
	gf sqli $domain/scans/gau/valid.txt | tee $domain/scans/gf/sqli.txt
}
gf_recon
