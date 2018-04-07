crashinfo
====

Display some initial information about kernel crash on illumos

#### Usage
<pre>
Usage: crashinfo [-a | -dmpt] [-v]  corefile  
</pre>
Example
<pre>
# crashinfo /var/crash/vmcore.0
core file /var/crash/0/vmcore.0 (64-bit) from lannister-57
operation system: 5.11 NexentaOS:d34295109d (i86pc)
hostid: 1890317a
image uuid: 1ba2e3a5-1f87-ef74-babc-83a066a10ae7
physmem: 33543585 (128G)
panic message: forced crash dump initiated at user request
crashtime: Tue Mar 27 08:49:16 2018
core size: 9853681664 (9.18G)
</pre>
