bcmdhd-dissector
================

Wireshark protocol dissector for brcmfmac host<->firmware communication protocols

Install instructions
--------------------
1) Copy *.lua to ~/.wireshark/plugins/ folder

Capturing with patched brcmfmac driver
-------------------------------------

The brcmfmac driver patch add dumps of firmware commands and events to kernel log. Using text2pcap
the kernel logs are converted to a pcap that can then be opened in wireshark with the lua dissector
plugins installed.

1) Patch prima driver with <pre>0001-Add-hexdump-logs-for-bcmdhd-dissector-tool.patch</pre>
2) Enable BRCMDBG config flag and build brcmfmac module.

3) Enable dissect debug prints:

   Either in runtime with: <pre>echo 0x00100000 > /sys/module/brcmfmac/parameters/debug</pre>
   Or at insmod with: <pre>insmod brcmfmac.ko debug=0x00100000</pre>

4) Capture kernel log <pre>adb shell cat /proc/kmsg | tee dump.txt</pre>
5) Convert to pcap: <pre>cat dump.txt | grep bcmdump | perl -pe 's/.{4}(.{12}).{20}(.+)/$1 $2/' | text2pcap -q -t "%s." -l 105 - dump.pcap</pre>
6) Open pcap file with wireshark
