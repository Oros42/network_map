#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author : Oros
# License : CC0 1.0 Universal
#
# documentations :
#	 http://secdev.org/projects/scapy/doc/usage.html
#	 http://sdz.tdct.org/sdz/manipulez-les-paquets-reseau-avec-scapy.html
#
#
# Install :
# apt-get install tcpdump graphviz imagemagick python-gnuplot python-crypto python-pyx python-scapy nmap python-pyspatialite python-geoip
#
# apt-get install dvips
# or
# apt-get install dvi2ps
#
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
last_insert_connexions=[]
last_insert_ips=[]
geo=None
nb_ip_added=0
country_pos={}


def clean_exit(signum, frame):
	global can_sniff
	can_sniff=False
	print('stop...')

def init_db():
	import commands
	global c
	global conn
	c.execute("CREATE TABLE if not exists connexions (  id INTEGER PRIMARY KEY AUTOINCREMENT, ip_from varchar(30), ip_to varchar(30), to_port varchar(30) DEFAULT NULL, proto varchar(8) DEFAULT NULL, UNIQUE(ip_from,ip_to,to_port,proto));")
	c.execute("""CREATE TABLE if not exists ips (  id INTEGER PRIMARY KEY AUTOINCREMENT,
											 ip varchar(30),
											 country_code varchar(6) DEFAULT NULL,
											 country_name TEXT DEFAULT NULL,
											 region_name TEXT DEFAULT NULL,
											 city TEXT DEFAULT NULL,
											 postal_code TEXT DEFAULT NULL,
											 latitude TEXT DEFAULT NULL,
											 longitude TEXT DEFAULT NULL,
											 UNIQUE(ip));""")
	c.execute("""CREATE TABLE if not exists infos (  id INTEGER PRIMARY KEY AUTOINCREMENT, key varchar(50), data TEXT DEFAULT NULL, UNIQUE(key, data));""")
	r=commands.getoutput("/sbin/ifconfig").split('adr:')
	i=1
	while i < len(r):
		c.execute("INSERT OR IGNORE INTO infos ( key, data) VALUES (?, ?);",("my_ip",r[i].split(' ')[0]))
		i+=1
	conn.commit()

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
			init_db()
			shutil.copy('/dev/shm/ips.db','ips.db')
	conn.text_factory = str

	if not os.path.isfile('geoip/GeoLiteCity.dat'):
		# FIXME
		# nouvelle base : http://dev.maxmind.com/geoip/geoip2/geolite2/
		print("geoip/GeoLiteCity.dat Not found !\nStart downloading http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz")
		import urllib, gzip
		glcgz = open("geoip/GeoLiteCity.dat.gz",'wb')
		glcgz.write(urllib.urlopen("http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz").read(20000000))
		glcgz.close()
		glcgz = gzip.open("geoip/GeoLiteCity.dat.gz",'rb')
		glc = open("geoip/GeoLiteCity.dat",'wb')
		glc.write(glcgz.read())
		glcgz.close()
		glc.close()
		os.remove("geoip/GeoLiteCity.dat.gz")

def close_db():
	conn.close()
	if os.path.isfile('/dev/shm/ips.db'):
		shutil.copy('/dev/shm/ips.db','ips.db')

def get_my_ip():
	c.execute("SELECT data FROM infos WHERE key='my_ip';")
	ips=[]
	for i in c.fetchall():
		ips.append(i[0])
	return ips

def add_ips(x):
	global nb_ip_added
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
		if not (x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),dport,proto) in last_insert_connexions:
			c.execute("INSERT OR IGNORE INTO connexions ( ip_from, ip_to, to_port, proto) VALUES (?, ?, ?, ?);",(x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),dport,proto))
			conn.commit()
			last_insert_connexions.append((x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),dport,proto))
			if last_insert_connexions > 100:
				last_insert_connexions.pop(0)

			for ip in [x.sprintf("%IP.src%"), x.sprintf("%IP.dst%")]:
				if not ip in last_insert_ips:
					info=geo.record_by_addr(ip)
					if info:
						if info['country_code']:
							info['country_code'] = str(info['country_code'])
						if info['country_name']:
							info['country_name'] = str(info['country_name'])
						if info['region_name']:
							info['region_name'] = str(info['region_name'])
						if info['city']:
							info['city'] = str(info['city'])

						c.execute("""INSERT OR IGNORE INTO ips ( ip, country_code, country_name, region_name, city, postal_code, latitude, longitude ) 
							VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",(ip, info['country_code'], info['country_name'], info['region_name'], info['city'], info['postal_code'], info['latitude'], info['longitude']))
						conn.commit()
					last_insert_ips.append(ip)
					if last_insert_ips > 100:
						last_insert_ips.pop(0)
				else:
					last_insert_ips.remove(ip)
					last_insert_ips.append(ip)
			nb_ip_added+=1
		else:
			# move top of list
			last_insert_connexions.remove((x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),dport,proto))
			last_insert_connexions.append((x.sprintf("%IP.src%"),x.sprintf("%IP.dst%"),dport,proto))

def start_sniff():
	import GeoIP
	global can_sniff
	global geo
	global nb_ip_added
	geo = GeoIP.open("geoip/GeoLiteCity.dat",GeoIP.GEOIP_MEMORY_CACHE | GeoIP.GEOIP_CHECK_CACHE)

	while can_sniff:
		try:
			sniff(prn=add_ips,count=20)
			if nb_ip_added >50:
				nb_ip_added=0
				if os.path.isfile('/dev/shm/ips.db'):
					shutil.copy('/dev/shm/ips.db','ips.db')
		except Exception:
			can_sniff=False
			continue

	conn.close()
	if os.path.isfile('/dev/shm/ips.db'):
		shutil.copy('/dev/shm/ips.db','ips.db')
		os.remove('/dev/shm/ips.db')

def get_uniques_ips():
	c.execute("SELECT ip_from FROM connexions WHERE ip_from!= '??' GROUP BY ip_from UNION SELECT ip_to FROM connexions WHERE ip_to!= '??' GROUP BY ip_to;")
	ips=[]
	for i in c.fetchall():
		ips.append(i[0])
	return ips

def get_nb_ips():
	print("Nb ips : {}".format(len(get_uniques_ips())))

def get_stat_me_top():
	c.execute("SELECT ip_to, to_port, proto, count(ip_from)  FROM connexions WHERE ip_to IN (SELECT data FROM infos WHERE key='my_ip') GROUP BY to_port,proto ORDER BY count(ip_from) DESC LIMIT 10;")
	a= c.fetchone()
	print("Top 10 of used port")
	print("My IP \t\t: port\t: proto\t: nb IP")
	while a:
		print("{}\t: {}\t: {}\t: {}".format((a[0] if len(a[0])>7 else a[0]+"\t"),a[1],a[2],a[3]))
		a= c.fetchone()

def geoip(to_port=None):
	if to_port:
		c.execute("SELECT country_code, country_name, count(ip) FROM ips, connexions WHERE ip=ip_from AND to_port='{}' GROUP BY country_code, country_name ORDER BY count(ip) DESC;".format(to_port))
		print("country rank on port : {}".format(to_port))
	else:
		c.execute("SELECT country_code, country_name, count(ip) FROM ips GROUP BY country_code, country_name ORDER BY count(ip) DESC;")
	print("rank : country_code : country_name : nb IP")
	a= c.fetchall()
	i = 1
	total=0
	for ip in a:
		print("{} : {} : {} : {}".format(str(i), ip[0],ip[1],ip[2]))
		i +=1
		total+=ip[2]
	print("Total IP {}".format(total))

def geoip_map():
	import BaseHTTPServer, mimetypes, urllib, re, csv, urlparse
	global country_pos
	with open('geoip/country_pos.csv', 'r') as csv_file:
		data = csv.reader(csv_file, delimiter=';', quotechar='"')
		data.next()
		for row in data:
			country_pos[row[0]]=(row[1],row[2])

	class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
		def not_found(self):
			self.send_response(404)
			self.send_header('Content-type','text/html')
			self.end_headers()
			self.wfile.write("Nope")

		def do_GET(self):
			content=''
			if self.path==u"/":
				self.send_response(200)
				self.send_header('Content-type','text/html')
				self.end_headers()
				self.wfile.write(open("./www/index.html","r").read())
			elif self.path in [u"/leaflet.css",u"/leaflet.js",u"/index.html",u"/images/marker-icon.png",u"/images/marker-icon1.png",u"/images/marker-icon2.png",u"/images/marker-icon3.png",u"/images/marker-icon4.png",u"/images/marker-shadow.png"]:
				localpath = urllib.unquote(self.path).decode("utf-8").replace(u"/",os.path.sep)[1:].replace(u"..",u".")
				if os.path.isfile("./www/"+localpath):
					ext = os.path.splitext("./www/"+localpath)[1].lower()
					mimetype = mimetypes.types_map[ext]
					self.send_response(200)
					self.send_header(u'Content-Type',mimetype)
					self.send_header(u'Content-Length',unicode(os.path.getsize("./www/"+localpath)))
					self.end_headers()
					self.wfile.write(open("./www/"+localpath,"rb").read())
				else:
					self.not_found()
			else:
				query=urlparse.parse_qs(urlparse.urlparse(self.path).query)
				if 's' in query:
					if 'countries' in query['s']:
						c.execute("SELECT country_code, country_name, count(ip) FROM ips GROUP BY country_code ORDER BY count(ip) DESC, country_code ASC;")
						self.send_response(200)
						self.send_header('Content-type','application/javascript')
						self.end_headers()
						content="country_codes=["
						for country in c.fetchall():
							try:
								content+="[\"{}\",\"{}\", {}, {}, {}],\n".format(country[0],country[1],country[2],country_pos[country[0]][0],country_pos[country[0]][1])
							except KeyError:
								print("Not found country code : "+country[0])
								continue
						self.wfile.write(content[0:-1]+"];");
					elif 'country' in query['s'] and 'c' in query and query['c']!=[]:
						regex = re.compile("^([A-Z0-9][A-Z0-9])$")
						if regex.search(query['c'][0]):
							self.send_response(200)
							self.send_header('Content-type','application/javascript')
							self.end_headers()
							content="[\n"
							c.execute("SELECT country_code, latitude, longitude, country_name, city, count(ip) FROM ips WHERE country_code='{}' GROUP BY city ORDER BY count(ip) DESC, city ASC;".format(query['c'][0]))
							for ip in c.fetchall():
								content+="[\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{}],\n".format(ip[0],ip[1],ip[2],ip[3],ip[4],ip[5])
							if content!="[\n":
								self.wfile.write(content[0:-2]+"\n]");
						else:
							self.not_found()
					elif 'ips' in query['s'] and 'lat' in query and 'lon' in query and 'c' in query and query['c']!=[] and query['lat']!=[] and query['lon']!=[]:
						regex = re.compile("^([A-Z0-9][A-Z0-9])$")
						num = re.compile("^(-?\d+\.?\d+)$")
						if regex.search(query['c'][0]) and num.search(query['lat'][0]) and num.search(query['lon'][0]):
							self.send_response(200)
							self.send_header('Content-type','application/javascript')
							self.end_headers()
							content="[\n"
							c.execute("SELECT ip FROM ips WHERE country_code='{}' AND latitude='{}' AND longitude='{}' ORDER BY ip ASC;".format(query['c'][0], query['lat'][0], query['lon'][0]))
							for ip in c.fetchall():
								content+="\"{}\",\n".format(ip[0])
							if content!="[\n":
								self.wfile.write(content[0:-2]+"\n]");
						else:
							self.not_found()
				else:
					self.not_found()
			return

	print "Listening on port 127.0.0.1:8088..."
	server = BaseHTTPServer.HTTPServer(('127.0.0.1', 8088), MyHandler)
	server.serve_forever()


def help():
	print("""Need parameters :
start : start sniffing (need root)
stop : stop sniffing (need root)
show : show connexions
nbip : number of IPs
top : top 10 of used port
geo [port] : rank of country
map : run server for javascript map (127.0.0.1:8088)

Exemples :
sudo ./sniffer.py start >/dev/null &
#sniff all IPs on the network

./sniffer.py map
Go on 127.0.0.1:8088

sudo ./sniffer.py stop

""")

if len(sys.argv) < 2:
	help()
	sys.exit(1)

action=sys.argv[1]

if action =="start":
	from scapy.all import sniff
	import signal
	signal.signal(signal.SIGTERM, clean_exit)
	load_db(True)
	start_sniff()
elif action == "stop":
	os.system('ps -C "sniffer.py start" -o pid=|xargs kill -15')
else:
	load_db(False)
	if action == "nbip":
		get_nb_ips()
	elif action == "top":
		get_stat_me_top()
	elif action == "geo":
		import GeoIP
		if len(sys.argv) < 3:
			geoip()
		else:
			geoip(sys.argv[2])
	elif action == "map":
		import GeoIP
		geoip_map()
	elif action == "updb":
		init_db()
	else:
		print("What?")
		help()
	close_db()
