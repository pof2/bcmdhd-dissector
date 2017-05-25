bcmdhd-dissector
================

Wireshark protocol dissector for brcmfmac host<->firmware communication protocols

Install instructions
--------------------
1) Copy *.lua to ~/.wireshark/plugins/ folder

2) Clone https://github.com/kanstrup/brcm80211-trace-cmd

3) export TRACE_CMD_PLUGIN_DIR environment to the path of your brmfmac.py file from above brcm80211-trace-cmd

Capturing with patched brcmfmac driver
-------------------------------------

The brcmfmac driver patch add tracepoint events with hexdump of firmware commands
and events. It also add support to dump the TX/RX data passed to/from chip. Then
use trace-cmd with the brcmfmac plugins to record and extract hexdump data and
convert to pcap format with text2pcap tool. The pcap file can then be opened in
wireshark with the lua dissector plugins installed.

1) Patch brcmfmac driver with <pre>0001-brcmfmac-Add-tracepoints-for-bcmdhd-dissector-tool.patch</pre>

2) Enable BRCMDBG config flag and build brcmfmac module.
3) Enable dissect debug prints:

   Control and event messages:
   <pre>echo 0x00100000 > /sys/module/brcmfmac/parameters/debug</pre>

   TX and RX data:
   <pre>echo 0x00200000 > /sys/module/brcmfmac/parameters/debug</pre>

   Both:
   <pre>echo 0x00300000 > /sys/module/brcmfmac/parameters/debug</pre>

   Can also be set at insmod with: <pre>insmod brcmfmac.ko debug=0x00300000</pre>

4) Start trace-cmd recording: <pre>trace-cmd record -e brcmfmac:brcmf_dissect_hexdump -e brcmfmac:brcmf_dissect_data_hexdump</pre>
5) Stop recording when done

6) Create trace-cmd report and let text2pcap tool convert to pcap format: <pre>trace-cmd report | text2pcap - dump.cap</pre>
7) Open pcap file with wireshark

Example dumps
-------------
The examples folder contains some dumps taken from a patched brcmfmac driver
