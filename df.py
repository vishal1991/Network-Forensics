#!/usr/bin/python

import dpkt
import socket
import urllib2
import optparse
import os
import subprocess
import pygeoip
import simplekml
import sys
import operator

def main():
# -------------------provide user options ------------------------------------------

	parser = optparse.OptionParser('bash clean.sh\n./df.py -h\n')
	parser.add_option('-p', dest='pcapfile', help='PCAP file')	
	parser.add_option('-b', dest='blacklistfile', help='Blacklisted IP addresses list')
	parser.add_option('-g', dest='geo', help='Location of GeoCityLite database')
	parser.add_option('-t', type='int', dest='limit', help='Packet threshold over which DDOS suspected')
	parser.add_option('-n', type='int', dest='port', help='Suspected Port number for DDOS attack')
	parser.add_option('-k', dest='kmlfile', help='kml file for malicious IP addresses')
	
	(options, args) = parser.parse_args()
	pcap_file = options.pcapfile
	blacklist_file = options.blacklistfile
	geo_file = options.geo
	kml_file = options.kmlfile
	threshold = options.limit
	port = options.port


# ----------------check for required files --------------------------------------------
	
	if blacklist_file == None or pcap_file == None or not os.path.isfile(blacklist_file) or not os.path.isfile(pcap_file):
		print parser.usage
		exit(0)
	if not os.path.isfile('script.sh'):
		print '\nPlease Download script.sh into current directory\n'
		exit(0)
	
	dict_blist = {}
	dict_pkt = {}
	city = ''
	country = ''
	lat = ''
	longt = ''
	kl = False
	attack = False

	if threshold != None and port != None:
		attack = True


# ---------------------Run bash script ------------------------------------------		

	subprocess.call(['bash', 'script.sh', blacklist_file, 'black_list.txt', pcap_file, 'outfile.csv'])

# ----------------- store all IP addresses and there respective count in dict_pkt -------------

	fdesc = open ('outfile.csv','r')

	for pkt in fdesc:
		pkt = pkt.strip()
		if pkt not in dict_pkt:
			dict_pkt[pkt] = 1
		else:
			dict_pkt[pkt] = dict_pkt[pkt] + 1

	fdesc.close()

# -----------------store Malicious IP addresses and there respective count in dict_blist

	fd = open ('black_list.txt', 'r')
	blacklist = []
	for line in fd:
		line = line.strip()
		dict_blist[line] = 0

	fd.close()


#-----------------Source and Destination port visualization -------------------------
	
	pcap_file  = dpkt.pcap.Reader(open(pcap_file))
	count = {}
	destport = {}
	srcport = {}
	dos = {}
	ddos = {}
	dosdesc = open('dos.tsv','w')
	dosdesc.write('letter\tfrequency\n')
	sddesc = open('SrcDst.tsv','w')
	sddesc.write('letter\tfrequency\n')
	dportdesc = open('dport.tsv', 'w')
	dportdesc.write('letter\tfrequency\n')
	sportdesc = open('sport.tsv', 'w')
	sportdesc.write('letter\tfrequency\n')

#-----------------------parsing PCAP file ---------------------

	for (ts, buff) in pcap_file:
		try:
			eth = dpkt.ethernet.Ethernet(buff)
			ip = eth.data
			src = socket.inet_ntoa(ip.src)
			dst = socket.inet_ntoa(ip.dst)
			tcp = ip.data

			sport = tcp.sport
			dport = tcp.dport
			if dport in destport:
				destport[dport] = destport[dport] + 1
			else:
				destport[dport] = 1
			if sport in srcport:
				srcport[sport] = srcport[sport] + 1
			else:
				srcport[sport] = 1

			flow = src + '-->' + dst
			if count.has_key(flow):
				count[flow] = count[flow] + 1
			else:
				count[flow] = 1

		
#-----------------------Identify DDOS attack ----------------------------------
			
			if attack == True:
				if dport == port:
					stream = src + '-->' + dst
					if dos.has_key(stream):
						dos[stream] = dos[stream] + 1
					else:
						dos[stream] = 1
			
		except Exception,e:
			pass

	if attack == True:
		for stream in dos:
			sent  = dos[stream]
			if sent > threshold:
				src = stream.split('-->')[0]
				dst = stream.split('-->')[1]
				blacklist.append(src)
				ddos[stream] = sent
				print '\n[+]Suspected DDOS attack with src: '+ str(src)+ ' and dst: ' + str(dst) + '\n'
		
#------------creating visulization files ---------------------
		
		for key, value in ddos.iteritems():
			dosdesc.write(str(key)+'\t'+str(value)+'\n')
		dosdesc.close()

	filedesc = open('ip.tsv', 'w')
	maldesc = open('maliciousip.tsv','w')
	filedesc.write('letter\tfrequency\n')
	maldesc.write('letter\tfrequency\n')
	for key, value in dict_pkt.iteritems():
		if value > 0  and len(key) >= 7 and len(key)<=15:
			filedesc.write(str(key)+'\t'+str(value)+'\n')
			if key in dict_blist.keys():
				dict_blist[key] = dict_blist[key] + value
				maldesc.write(str(key)+'\t'+str(value)+'\n')
				blacklist.append(key)
	filedesc.close()
	maldesc.close()
	
	for key, value in count.iteritems():
		sddesc.write(str(key)+'\t'+str(value)+'\n')

	for key, value in destport.iteritems():
		dportdesc.write(str(key)+'\t'+str(value)+'\n')

	for key, value in srcport.iteritems():
		sportdesc.write(str(key)+'\t'+str(value)+'\n')
		
	sddesc.close()
	dportdesc.close()
	sportdesc.close()
	
# - --------------------- Geocoding KML file ------------------	

	if kml_file != None:
		if geo_file == None:
			print parser.usage
			print 'GeoCityLite database file missing'
			exit(0)
		gi = pygeoip.GeoIP(geo_file)
		kmlf = open(kml_file,'wb')
		kml = simplekml.Kml()
	
		for entry in blacklist:
			try:
				rec = gi.record_by_name(entry)
				city = rec['city']
				country = rec['country_name']
				longt = rec['longitude']
				lat = rec['latitude']

				kml.newpoint(name=city or entry, coords=[(lat,longt)])
				kml.save(kml_file)

			except Exception, e:
				pass
		

main()

