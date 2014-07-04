#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author : Oros
#
# documentations :
#	 http://secdev.org/projects/scapy/doc/usage.html
#	 http://sdz.tdct.org/sdz/manipulez-les-paquets-reseau-avec-scapy.html
#
# Install :
# apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx python-scapy nmap
# apt-get install python-pyspatialite
# sudo ./sniffer.py
#
import sys
from pyspatialite import dbapi2 as sqlite3
import socket

conn = sqlite3.connect('ips.db')
c = conn.cursor()
c.execute("CREATE TABLE if not exists connexions (  id INTEGER PRIMARY KEY AUTOINCREMENT, ip_from varchar(30), ip_to varchar(30), to_port varchar(30) DEFAULT NULL, UNIQUE(ip_from,ip_to,to_port));")
conn.commit()

def get_my_ip():
	# bof bof
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("gnu.org",80))
	ip=s.getsockname()[0]
	s.close()
	return ip

def add_ips(x):
	c.execute("INSERT OR IGNORE INTO connexions ( ip_from, ip_to, to_port) VALUES ('{}', '{}', '{}');".format(x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),x.sprintf("%TCP.dport%")))
	conn.commit()

def run_sniff():
	while 1:
		sniff(prn=add_ips,count=100)

def show_ips():
	c.execute("SELECT ip_from, ip_to, to_port FROM connexions;")
	a= c.fetchone()
	print("num : IP from -> IP to : Port")
	i=1
	while a:
		print("{} : {} -> {} : {}".format(i,a[0],a[1],a[2]))
		a= c.fetchone()
		i+=1

def get_uniques_ips():
	c.execute("SELECT ip_from FROM connexions GROUP BY ip_from;")
	a= c.fetchone()
	ips=[]
	while a:
		if a[0] not in ips and a[0] != "??":
			ips.append(a[0])
		a= c.fetchone()

	c.execute("SELECT ip_to FROM connexions WHERE ip_to NOT IN ('{}') GROUP BY ip_to;".format("','".join(ips)))
	a= c.fetchone()
	while a:
		if a[0] not in ips and a[0] != "??":
			ips.append(a[0])
		a= c.fetchone()
	return ips

def gen_map():
	res,unans = traceroute(get_uniques_ips(),dport=[80,443],maxttl=20,retry=-2)
	res.graph() 
	res.graph(type="ps",target="| lp")
	res.graph(target="> graph.svg")

def gen_links():
	nodes=[]
	for ip in get_uniques_ips():
		nodes.append({ 'data': { 'id': ip, 'name': ip, 'weight': '100', 'height': '100' } })
	
	edges=[]
	c.execute("SELECT ip_from, ip_to FROM connexions;")
	a= c.fetchone()
	while a:
		if a[0] != "??" and a[0] != "??":
			edges.append({ 'data': { 'source': a[0], 'target': a[1] } })
		a= c.fetchone()

	elements={'nodes':nodes,'edges':edges}

	with io.open('elements.js', 'w', encoding='utf-8') as f:
		f.write("var nb_ips="+unicode(str(len(nodes)))+";")
		f.write("var elements="+unicode(json.dumps(elements, ensure_ascii=False))+";")

def get_ips():
	i=0;
	for ip in get_uniques_ips():
		i+=1
		print("{} : {}".format(i,ip))
	print("\nNb ips : {}".format(i))

def get_nb_ips():
	print("Nb ips : {}".format(len(get_uniques_ips())))


def get_stat():
	my_ip=get_my_ip()
	c.execute("SELECT to_port, count(id) FROM connexions WHERE ip_to='{}' group by to_port order by to_port;".format(my_ip))
	print(c.fetchall)
	a= c.fetchone()
	print("port : nb connection on {}".format(my_ip))
	while a:
		print("{} : {}".format(a[0],a[1]))
		a= c.fetchone()
	get_nb_ips()

def help():
	print("""Need parameters :
run : start sniffing
show : show connexions
ip : list all IPs
js : dump the DB into a JS file
nbip : number of IPs
stat : show nb connection by port

Exemples :
In Terminal 1
sudo ./sniffer.py run
#sniff all IPs on the network

In Terminal 2
./sniffer.py show
192.168.0.42 -> 192.168.0.1
192.168.0.1 <- 192.168.0.42
192.168.0.42 -> 192.168.0.64
...""")

if len(sys.argv) < 2:
    help()
    sys.exit(1)

action=sys.argv[1]
if action == "show":
	show_ips()
elif action == "map":
	gen_map()
elif action == "js":
	import json
	import io
	gen_links()
elif action == "ip":
	get_ips()
elif action == "nbip":
	get_nb_ips()
elif action =="run":
	from scapy.all import *
	run_sniff()
elif action == "stat":
	get_stat()	
else:
	print("What?")
	help()
