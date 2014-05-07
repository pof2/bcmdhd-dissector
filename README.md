bcmdhd-dissector
================

cat dump.txt | grep bcmdump | perl -pe 's/.{4}(.{12}).{20}(.+)/$1 $2/' | text2pcap -q -t "%s." -l 105 - dump.pcap
