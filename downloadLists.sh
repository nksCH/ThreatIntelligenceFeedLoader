#!/bin/bash 
#Script that downloads the Emerging Threats - Shadowserver C&C List, #Spamhaus 
#DROP Nets, Dshield Top Attackers, Known RBN Nets #and IPs, Compromised IP List, 
#RBN Malvertisers IP List;  AlienVault - IP Reputation Database; ZeuS Tracker - 
#IP Block List; SpyEye Tracker - IP Block List; Palevo Tracker - IP Block List; 
#SSLBL - SSL Blacklist; Malc0de Blacklist; Binary Defense Systems Artillery 
#Threat Intelligence Feed and Banlist Feedand then strips any junk/formatting 
#that can't be used and creates Splunk-ready inputs.    
#   
#Feel free to use and modify as needed   
#   
#Authors:
# * Philipp Promeuschel 
#   based on work from Adrian Daucourt based on work from Keith
#   (https://github.com/shift/docker-suricata/blob/master/files/blacklist.sh)
#==============================================================================
#Fix error when calling script from Splunk
#==============================================================================

unset LD_LIBRARY_PATH

#==============================================================================
#Emerging Threats - Shadowserver C&C List, Spamhaus DROP Nets, Dshield Top
#Attackers
#==============================================================================
rm  /root/blocklists/*

wget http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O /tmp/emerging-Block-IPs.txt --no-check-certificate -N

cat /tmp/emerging-Block-IPs.txt | sed -e '1,/#Spamhaus DROP Nets/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed 's/$/,Spamhaus IP/' >> /root/blocklists/emerging_threats_spamhaus_drop_ips.txt

cat /tmp/emerging-Block-IPs.txt | sed -e '1,/#Dshield Top Attackers/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed 's/$/,Dshield IP/' >> /root/blocklists/emerging_threats_dshield_ips.txt

rm /tmp/emerging-Block-IPs.txt

#==============================================================================
#Emerging Threats - Compromised IP List
#==============================================================================

wget http://rules.emergingthreats.net/blockrules/compromised-ips.txt -O /tmp/compromised-ips.txt --no-check-certificate -N

cat /tmp/compromised-ips.txt | sed -n '/^[0-9]/p' | sed 's/$/,Compromised IP/' >> /root/blocklists/emerging_threats_compromised_ips.txt

rm /tmp/compromised-ips.txt

#==============================================================================
#Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
#==============================================================================

wget http://www.binarydefense.com/banlist.txt -O /tmp/binary_defense_ips.txt --no-check-certificate -N

cat /tmp/binary_defense_ips.txt | sed -n '/^[0-9]/p' | sed 's/$/,Binary Defense IP/' >> /root/blocklists/binary_defense_ban_list.txt

rm /tmp/binary_defense_ips.txt

#==============================================================================
#AlienVault - IP Reputation Database
#==============================================================================

wget https://reputation.alienvault.com/reputation.snort.gz -P /tmp --no-check-certificate -N

gzip -d /tmp/reputation.snort.gz
cat /tmp/reputation.snort | sed -n '/^[0-9]/p' | sed 's/ # /,AlienVaul Flagged: /' >> /root/blocklists/av_ip_rep_list.txt

rm /tmp/reputation.snort

#==============================================================================
#SSLBL - SSL Blacklist
#==============================================================================

wget https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O /tmp/sslipblacklist.csv --no-check-certificate -N

cat /tmp/sslipblacklist.csv | sed -n '/^[0-9]/p' | cut -d',' -f1,3 | sed "s/ //" | sed 's/$/ SSLBL IP/' >> /root/blocklists/sslipblacklist.txt

rm /tmp/sslipblacklist.csv

#==============================================================================
#ZeuS Tracker - IP Block List
#==============================================================================

wget https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist -O /tmp/zeustracker.txt --no-check-certificate -N

cat /tmp/zeustracker.txt | sed -n '/^[0-9]/p' | sed 's/$/,ZeuS Tracker IP/' >> /root/blocklists/zeus_ip_block_list.txt

rm /tmp/zeustracker.txt

#==============================================================================
#Abuse.ch DNS Blacklist - IP Block List
#==============================================================================

wget https://sslbl.abuse.ch/downloads/ssl_extended.csv -O /tmp/dnsblocklist.txt --no-check-certificate -N

cat /tmp/dnsblocklist.txt | cut -d ',' -f3 | sed -n '/^[0-9]/p' | sed 's/$/,Abuse.ch DNSBlockList/' >> /root/blocklists/dnsblocklist_ip_block_list.txt

rm /tmp/dnsblocklist.txt

#==============================================================================
#Abuse.ch Ransomware Tracker - IP Block List
#==============================================================================

wget https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt -O /tmp/ransomtracker.txt --no-check-certificate -N

cat /tmp/ransomtracker.txt | sed -n '/^[0-9]/p' | sed 's/$/,Abuse.ch Ransomware Tracker IP/' >> /root/blocklists/ransom_ip_block_list.txt

rm /tmp/ransomtracker.txt


#==============================================================================
#Feodo Tracker - IP Block List
#==============================================================================

wget https://feodotracker.abuse.ch/blocklist/?download=ipblocklist -O /tmp/feodotracker.txt --no-check-certificate -N

cat /tmp/feodotracker.txt | sed -n '/^[0-9]/p' | sed 's/$/,Feodo IP/' >> /root/blocklists/feodo_ip_block_list.txt

rm /tmp/feodotracker.txt

#==============================================================================
#Malc0de - Malc0de Blacklist
#==============================================================================

wget http://malc0de.com/bl/IP_Blacklist.txt -O /tmp/IP_Blacklist.txt --no-check-certificate -N

cat /tmp/IP_Blacklist.txt | sed -n '/^[0-9]/p' | sed 's/$/,Malc0de IP/' >> /root/blocklists/malc0de_black_list.txt

rm /tmp/IP_Blacklist.txt

echo "mal_ip,mal_description" > /root/blocklists/combined_malwaredomainslist
cat /root/blocklists/*.txt >> /root/blocklists/combined_malwaredomainslist
wc -l /root/blocklists/combined_malwaredomainslist
uniq /root/blocklists/combined_malwaredomainslist /root/blocklists/combined_malwaredomainslist_uniq
wc -l /root/blocklists/combined_malwaredomainslist*
gzip /root/blocklists/combined_malwaredomainslist_uniq
