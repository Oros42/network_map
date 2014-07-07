network_map
===========

/!\ Work in progress !


Setup
=====

```sudo apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx python-scapy nmap python-pyspatialite```

Run
===

1. Start sniffing :  
```sudo ./sniffer.py start```  
  
2. Watch who talk to who (You can run it in an other termial during the sniffing) :  
```./sniffer.py show```  
  
3. You can create a svg graph :  
```./sniffer.py map```  
  
4. Or a js graph :  
```./sniffer.py js```  
	and open index.html

5. Stop sniffing :  
```sudo ./sniffer.py stop```  

Licence
=======

cytoscape.min.js comes from https://github.com/cytoscape/cytoscape.js/  
  
All other files are under CC0 1.0 Universal  
