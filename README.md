network_map
===========

/!\ Work in progress !


Setup
=====

```sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx python-scapy nmap python-pyspatialite python-geoip```  
  
```sudo apt-get install dvips```  
or  
```sudo apt-get install dvi2ps```  
  

Run
===

1. Start sniffing :  
```sudo ./sniffer.py start```  
  
2. You can watch a map with positions of IPs :  
```./sniffer.py map```  
Go on 127.0.0.1:8088  
  
3. Stop sniffing :  
```sudo ./sniffer.py stop```  

Licence
=======

sniffer.py is under CC0 1.0 Universal  
