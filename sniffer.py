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
import os
import shutil

can_sniff=True
c=None
conn=None

def clean_exit(signum, frame):
	global can_sniff
	can_sniff=False
	print('stop...')

def load_db(write):
	global c
	global conn
	if os.path.isfile('/dev/shm/ips.db'):
		conn = sqlite3.connect('/dev/shm/ips.db',15)
		c = conn.cursor()
	else:
		if os.path.isfile('ips.db'):
			if write:
				shutil.copy('ips.db','/dev/shm/ips.db')
				conn = sqlite3.connect('/dev/shm/ips.db',15)
			else:
				conn = sqlite3.connect('ips.db',15)
			c = conn.cursor()
		else:
			conn = sqlite3.connect('/dev/shm/ips.db',15)
			c = conn.cursor()
			c.execute("CREATE TABLE if not exists connexions (  id INTEGER PRIMARY KEY AUTOINCREMENT, ip_from varchar(30), ip_to varchar(30), to_port varchar(30) DEFAULT NULL, proto varchar(8) DEFAULT NULL, UNIQUE(ip_from,ip_to,to_port,proto));")
			conn.commit()
			shutil.copy('/dev/shm/ips.db','ips.db')

def get_my_ip():
	# bof bof
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("gnu.org",80))
	ip=s.getsockname()[0]
	s.close()
	return ip

def add_ips(x):
	if can_sniff:
		proto=x.sprintf("%IP.proto%")
		if proto == "tcp":
			dport=x.sprintf("%TCP.dport%")
		elif proto == "udp":
			dport=x.sprintf("%UDP.dport%")
		elif proto == "icmp":
			dport='-'
		else:
			dport='?'

		c.execute("INSERT OR IGNORE INTO connexions ( ip_from, ip_to, to_port, proto) VALUES (?, ?, ?, ?);",(x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),dport,proto))
		conn.commit()

def start_sniff():
	global can_sniff
	
	while can_sniff:
		try:
			sniff(prn=add_ips,count=20)
			shutil.copy('/dev/shm/ips.db','ips.db')
		except Exception:
			can_sniff=False
			continue

	shutil.move('/dev/shm/ips.db','ips.db')

def show_ips():
	c.execute("SELECT ip_from, ip_to, to_port, proto FROM connexions;")
	a= c.fetchone()
	print("num : IP from -> IP to : Port ; proto")
	i=1
	while a:
		print("{} : {} -> {} : {} ; {}".format(i,a[0],a[1],a[2],a[3]))
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
	c.execute("SELECT to_port, proto, count(id), ip_from FROM connexions WHERE ip_to='{}' group by to_port,proto order by to_port;".format(my_ip))
	a= c.fetchone()
	print("port : proto : nb connection on {} (from IP)".format(my_ip))
	while a:
		if a[2] == 1:
			print("{} : {} : {} ({})".format(a[0],a[1],a[2],a[3]))
		else:
			print("{} : {} : {}".format(a[0],a[1],a[2]))
		a= c.fetchone()


	c.execute("SELECT to_port, proto, count(id),ip_to, ip_from FROM connexions WHERE ip_to!='{0}' and ip_from!='{0}' group by ip_to, to_port,proto order by to_port;".format(my_ip))
	a= c.fetchone()
	ip=''
	while a:
		if ip != a[3]:
			ip=a[3]
			print("\n\nport : proto : nb connection on {} (from IP)".format(ip))
		if a[2] == 1:
			print("{} : {} : {} ({})".format(a[0],a[1],a[2],a[4]))
		else:
			print("{} : {} : {}".format(a[0],a[1],a[2]))
		a= c.fetchone()

	print("\n")
	get_nb_ips()


def get_stat_to():
	c.execute("SELECT ip_to, to_port, proto, ip_from  FROM connexions WHERE 1 order by to_port;")
	a= c.fetchone()
	ip=''
	while a:
		if ip != a[3]:
			ip=a[3]
			print("\nConnection from {}".format(ip))
			print("IP, port, proto")

		print("{} : {} : {}".format(a[0],a[1],a[2]))
		a= c.fetchone()

def get_stat_me():
	my_ip=get_my_ip()
	c.execute("SELECT ip_to, to_port, proto  FROM connexions WHERE ip_from='{}' group by to_port,proto order by to_port;".format(my_ip))
	a= c.fetchone()
	print("Connection from {}".format(my_ip))
	print("IP, port, proto")
	while a:
		print("{} : {} : {}".format(a[0],a[1],a[2]))
		a= c.fetchone()

def help():
	print("""Need parameters :
start : start sniffing (need root)
stop : stop sniffing (need root)
show : show connexions
ip : list all IPs
js : dump the DB into a JS file
nbip : number of IPs
stat : show nb connection by port

Exemples :
sudo ./sniffer.py start >/dev/null &
#sniff all IPs on the network

./sniffer.py show
192.168.0.42 -> 192.168.0.1
192.168.0.1 <- 192.168.0.42
192.168.0.42 -> 192.168.0.64
...

sudo ./sniffer.py stop

""")

if len(sys.argv) < 2:
    help()
    sys.exit(1)

action=sys.argv[1]

if action =="start":
	from scapy.all import *
	import signal
	signal.signal(signal.SIGTERM, clean_exit)
	load_db(True)
	start_sniff()
elif action == "stop":
	os.system('ps -C "sniffer.py start" -o pid=|xargs kill -15')
else:
	load_db(False)
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
	elif action == "stat":
		get_stat()
	elif action == "to":
		get_stat_to()
	elif action == "me":
		get_stat_me()
	else:
		print("What?")
		help()

conn.close()
