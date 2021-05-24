#!/bin/bash

domain=$1
wordlist="/root/wordlist/all.txt"
resolvers="/root/resolver.txt"

mkdir -p $domain $domain/sources $domain/Recon $domain/Recon/nuclei $domain/Recon/wayback $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/masscan

passive_enum(){
    findomain -q -f /mainData/$file -r -u findomain_subdomains.txt
    subfinder -d $domain -o $domain/sources/subfinder_subdomains.txt
    assetfinder -subs-only $domain | tee $domain/sources/assetfinder_subdomains.txt 
    amass enum -passive -d $domain -o $domain/sources/amass_subdomains.txt

    sort -u $domain/sources/*_subdomains.txt -o subdomains.txt
    cat $domain/sources/subdomains.txt | rev | cut -d . -f 1-3 | rev | sort -u | tee $domain/sources/root_subdomains.txt
    cat $domain/sources/*.txt | sort -u > $domain/sources/domains.txt

}

brute_subdomains(){
    #agregar a active enum, agregar alterations en active
    shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt
}


resolving_domains(){
    # cambiar por puredns
    shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domains.txt -r $resolvers
}



http_prob(){
    cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
}



scanner(){
   cat $domain/Recon/httpx.txt nuclei -t /root/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt
   cat $domain/Recon/httpx.txt nuclei -t /root/nuclei-templates/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilities.txt
   cat $domain/Recon/httpx.txt nuclei -t /root/nuclei-templates/files/ -c 50 -o $domain/Recon/nuclei/files.txt
}


wayback_data(){
    cat $domain/domains.txt | gau | tee $domain/Recon/wayback/tmp.txt
    cat $domain/Recon/wayback/tmp.txt | egrep -v "\.woff|\.ttf|\.svg|\.png|\.jpeg|\.ico|\.eot|\.css" | sed 's/:80//g;s/:443//g' | sort -u > $domain/Recon/wayback/wayback.txt
    rm $domain/Recon/wayback/tmp.txt

}


valid_urls(){
    fuzzer -c -u "FUZZ" -w $domain/Recon/wayback/wayback.txt -mc 200 -of csv -o $domain/Recon/wayback/valid-temp.txt
    cat $domain/Recon/wayback/valid-temp.txt | grep http | awk -F "," '{print $1}' > $domain/Recon/wayback/valid.txt
    rm  $domain/Recon/wayback/valid-temp.txt
}


gf_patterns(){
    gf xss $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/xss.txt
    gf sqli $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/sqli.txt
    gf sqli $domain/Recon/wayback/valid.txt | tee $domain/Recon/gf/sqli.txt
}


custom_wordlist(){
    cat $domain/Recon/wayback/wayback.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt
    cat $domain/Recon/wayback/wayback.txt | unfutl -unique keys > $domain/Recon/wordlist/keys.txt
}


get_ips(){
    massdns -r $resolvers -t A -o S -w $domain/Recon/masscan/results.txt $domain/domains.txt
    gf ip $domain/Recon/masscan/results.txt | sort -u > $domain/Recon/masscan/ip.txt
}



passive_enum
active_enum
resolving_domains

http_prob
scanner
wayback_data
valid_urls
gf_patterns
custom_wordlist
get_ips
