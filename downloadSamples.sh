#!/bin/bash
# Download Samples for Network Analysis 
mkdir samples
cd samples
mkdir logs
cd logs
wget "http://www.secrepo.com/maccdc2012/conn.log.gz"
wget "http://www.secrepo.com/maccdc2012/dhcp.log.gz"
wget "http://www.secrepo.com/maccdc2012/dns.log.gz"
wget "http://www.secrepo.com/maccdc2012/files.log.gz"
wget "http://www.secrepo.com/maccdc2012/ftp.log.gz"
wget "http://www.secrepo.com/maccdc2012/http.log.gz"
wget "http://www.secrepo.com/maccdc2012/notice.log.gz"
wget "http://www.secrepo.com/maccdc2012/signatures.log.gz"
wget "http://www.secrepo.com/maccdc2012/smtp.log.gz"
wget "http://www.secrepo.com/maccdc2012/ssh.log.gz"
wget "http://www.secrepo.com/maccdc2012/ssl.log.gz"
wget "http://www.secrepo.com/maccdc2012/tunnel.log.gz"
wget "http://www.secrepo.com/maccdc2012/weird.log.gz"
gunzip *
rm *.gz
cd ..
mkdir snort
cd snort
wget "http://www.secrepo.com/maccdc2012/maccdc2012_fast_alert.7z"
wget "http://www.secrepo.com/maccdc2012/maccdc2012_full_alert.7z"
7z x maccdc2012_fast_alert.7z
7z x maccdc2012_full_alert.7z
rm *.7z
