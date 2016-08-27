#!/usr/bin/env python

import sys
import argparse
import nfqueue
from time import sleep
from scapy.all import *
   
def parse_arguments():

	optParser = argparse.ArgumentParser()

	optParser.add_argument("--iPacketDelay", help="set packet delay value")
	optParser.add_argument("--iTOS", help="set TOS value", action="store_true")
	optParser.add_argument("--iFrag", help="set fragmentation")
	optParser.add_argument("--cFrag", help="set fragmentation with chaff", action="store_true")
	optParser.add_argument("--cfragDup", help="set fragmentation with duplicate fragments", action="store_true")
	optParser.add_argument("--iFragOverlapp", help="set fragmentation with chaff and overlapping fragments", action="store_true")
	optParser.add_argument("--iUrg", help="set urgent pointer with chaff trailer", action="store_true")
	optParser.add_argument("--iTimestamp", help="skew tsval in TCP options", action="store_true")
	optParser.add_argument("--cSequence", help="wrap around initial sequence number", action="store_true")
	optParser.add_argument("--cFin", help="set Fin chaff", action="store_true")
	optParser.add_argument("--cChecksum", help="set checksum", action="store_true")
	optParser.add_argument("--cSegmentOverlapp", help="set segment Overlapp")
	optParser.add_argument("-ttl", help="sets IDS ttl for chaff evasions")

	return optParser.parse_args()

def main():

	logo = """
                	       _____                                               
 	         _____  ___   / ___/  _____  ____ _    ____    __  __  _____       
	 ______ /____/ / _ \  \__ \  / ___/ / __ `/   / __ \  / / / / /____/ ______
	/_____//____/ /  __/ ___/ / / /__  / /_/ /   / /_/ / / /_/ / /____/ /_____/
        	      \___/ /____/  \___/  \__,_/   / .___/  \__, /                
                	                           /_/      /____/                 
	"""

	print logo


	if not os.geteuid() == 0:
		exit("\nPlease run as root\n")

	options = { "packetdelay": False, "tos": False, "frag": False, "chaff_frag": False, 
		    "frag_dup": False, "frag_overlapp": False, "urg": False, "timestamp": False, 
		    "sequence": False, "fin": False, "checksum": False, "segment_overlapp": False, "ttl": False}

	opt = parse_arguments()
	
	if opt.iPacketDelay:
		options['packetdelay'] = opt.iPacketDelay
	if opt.iTOS:
		options['tos'] = opt.iTOS
	if opt.iFrag:
		options['frag'] = opt.iFrag
	if opt.cFrag:
		options['chaff_frag'] = opt.cFrag
	if opt.cfragDup:
		options['frag_dup'] = opt.cfragDup
	if opt.iFragOverlapp:
		options['frag_overlapp'] = opt.iFragOverlapp
	if opt.iUrg:
		options['urg'] = opt.iUrg
	if opt.iTimestamp:
		options['timestamp'] = opt.iTimestamp
	if opt.cSequence:
		options['sequence'] = opt.cSequence
	if opt.cFin:
		options['fin'] = opt.cFin
	if opt.cChecksum:
		options['checksum'] = opt.cChecksum
	if opt.cSegmentOverlapp:
		options['segment_overlapp'] = opt.cSegmentOverlapp
	if opt.ttl:
		options['ttl'] = opt.ttl

	evader = Evader(options)

	q = nfqueue.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(evader.evade)
	q.create_queue(0)
	try:
		q.try_run() # Main loop
	except KeyboardInterrupt:
		q.unbind(socket.AF_INET)
	q.close()

class Evader():

	def __init__(self, args):
		self.packetdelay = args['packetdelay']
		self.tos = args['tos']
		self.frag = args['frag']
		self.chaff_frag = args['chaff_frag']
		self.frag_dup = args['frag_dup']
		self.frag_overlapp = args['frag_overlapp']
		self.urg = args['urg']
		self.timestamp = args['timestamp']
		self.sequence = args['sequence']
		self.fin = args['fin']
		self.checksum = args['checksum']
		self.segment_overlapp = args['segment_overlapp']
		self.ttl = args['ttl']

	def call_evasion(self, p, evasion):
		if type(p) == list:
			for packet in p:
				retVal=evasion(packet)
		else:
			retVal=evasion(p)
		
		return retVal

	def evade(self, stuff, payload):
		data = payload.get_data()
    		pkt = IP(data)
    		etcp = ETCP()
		eip = EIP()

		if (self.tos):
			eip.setTOS(self.tos)
			pkt = self.call_evasion(pkt, eip.iTOS)

		if (self.frag):
			eip.setFragSize(self.frag)
			pkt = self.call_evasion(pkt, eip.iFrag)

		if (self.chaff_frag):
			pkt = self.call_evasion(pkt, eip.cFrag)

		if (self.frag_dup):
			pkt = self.call_evasion(pkt, eip.cFragDup)

		if (self.frag_overlapp):
			pkt = eip.iFragOverlapp(pkt)
		if (self.urg):
			pkt = self.call_evasion(pkt, etcp.iUrg)
		if (self.timestamp):
			pkt = self.call_evasion(pkt, etcp.iTimestamp)
		if (self.sequence):
			pkt = self.call_evasion(pkt, etcp.cSequence)
		if (self.fin):
			pkt = self.call_evasion(pkt, etcp.cFin)
		if (self.checksum):
			pkt = self.call_evasion(pkt, etcp.cChecksum)
		if (self.segment_overlapp):
			etcp.setSegmentSize(self.segment_overlapp)
			pkt = self.call_evasion(pkt, etcp.cSegmentOverlapp) 
			
		if (self.packetdelay):
			eip.setDelay(self.packetdelay)
			pkt = self.call_evasion(pkt, eip.iPacketDelay)

		send(pkt)
		payload.set_verdict(nfqueue.NF_DROP)

class EIP():
	def genChaffPayload(self, size):
		chaff = ''
		for i in range(size):
			c = random.choice(string.ascii_uppercase)
			chaff += c
		return chaff
	def iPacketDelay(self, p): #requires a single packet, returns a single packet
		sleep(float(self.delay))
		return p

	def iTOS(self, p): #requires a single packet, returns a single packet
		p.tos = self.tos
		p.show2
		return p

	def iFrag(self, p): #requires a single packet, returns a list
		if(p[IP].len > 40):
			p = fragment(p, self.fragsize)
		return p

	def cFrag(self, p): #requires a single packet, returns single packet
		if(packet.flags == 0x3 and packet.frag > 0):
			
			chaffPayload = genChaffPayload(p.load)
			p2 = p.copy
			p2.ttl = self.ttl
			p2.load = chaffPayload
			p2.show2			
			
		return p2

	def cfragDup(self, p): #requires a single packet, returns a single packet
		if (packet.flags == 0x3 and packet.frag > 0):
			f2 = f.copy
			f2.ttl = self.ttl
		return p

	def iFragOverlapp(self, p): #requires a list, returns a list
		count = 0
		for packet in p:
			
			if (count% 2 == 0 and count > 0):
				
				payload1 = p[count-1].getlayer(Raw).load
				payload2 = packet.getlayer(Raw).load
		
				del(packet[IP].payload)
				del(packet[IP].chksum)
				del(packet[IP].len)
				del(p[count-1][IP].payload)
		
				chaffPayload = self.genChaffPayload(len(payload1))
				overlappPayload = payload1 + payload2
		
				packet.add_payload(overlappPayload)
				packet.show2
				p[count-1].add_payload(chaffPayload)
				old = p[count-1].frag
				p[count-1].frag = packet.frag
				packet.frag = old
			count=count+1

		return p

	def setDelay(self, delay):
		self.delay = delay

	def setFragSize(self, fragsize):
		self.fragsize = int(fragsize)

	def setTOS(self, tos):
		self.tos = int(tos)

class ETCP():

	def __init__(self):
		self.FIN = 0x01
		self.SYN = 0x02
		self.RST = 0x04
		self.PSH = 0x08
		self.ACK = 0x10
		self.URG = 0x20
		self.ECE = 0x40
		self.CWR = 0x80

	def split(self, array, size):
		new_array = []
		size_counter = size
		for i in range(len(array)/size):
			if(size_counter == size):
				new_array.append(array[:size_counter])
			else:
				new_array.append(array[(size_counter-size):size_counter])
			size_counter += size

		return new_array

	def genChaffPayload(self, size):
		chaff = ''
		for i in range(size):
			c = random.choice(string.ascii_uppercase)
			chaff += c
		return chaff

	def iUrg(self, p): #requires a single packet, returns a single packet
		if(TCP in p and p.haslayer(Raw)):
			payload = p.getlayer(Raw).load
			payload_size = len(payload)
			chaff = self.genChaffPayload(8)
			payload += chaff
			p[TCP].add_payload(payload)
			p[TCP].flags = "PUA"
			p[TCP].urgptr = payload_size
			p.show2
		return p

	def iTimestamp(self, p): #requires a single packet, returns a single packet
		if(TCP in p and p[TCP].options != None):
			ts = p[TCP].options[2][1][0]
			ts = ts - 1
			TimeStamp = (ts, p[TCP].options[2][1][1])
			TSNew = (p[TCP].options[2][0], TimeStamp)
			p[TCP].options[2] = TSNew
			p.show2
		return p

	def cSequence(self, p): #requires a single packet, returns a single packet
		if (TCP in p and p[TCP].flags == 18):	
			p2 = p.copy()
			p2[TCP].seq = 0xFFFFFFFF - random.randint(1,8)
			src = p2[IP].src
			p2[IP].src = p2[IP].dst
			p2[IP].dst = src
			p2[IP].ttl = self.ttl
			p2.show2
		return p

	def cFin(self, p): #requires a single packet, returns a single packet
		if (TCP in p and p[TCP].flags & self.SYN and p[TCP].flags & self.ACK):
			p2 = p.copy()
			p2[TCP].flags = "F"
			src = p2[IP].src
			p2[IP].src = p2[IP].dst
			p2[IP].dst = src
			p2[IP].ttl = self.ttl
			p2.show2

		return p2

	def cChecksum(self, p): #requires a single packet, returns a single packet
		if(TCP in p):
			p2 = p.copy()
			p2[TCP].chksum += random.randint(1,16)
			p2[IP].ttl = self.ttl
			p2.show2

		return p2

	def cSegmentOverlapp(self, p): #requires a single packet, returns a list

		segments = []

		if (TCP in p and p[TCP].flags & self.ACK and p.haslayer(Raw) ):		
	
			segment_payload = p.getlayer(Raw).load

			split_segments = []
			split_segments = self.split(segment_payload, self.segsize)	
			

			for s in range(len(split_segments)):
				if s == 0:
					new_packet = p.copy()
					del(new_packet[IP].chksum)
					del(new_packet[IP].len)
					del(new_packet[TCP].payload)
					new_packet[TCP].payload = split_segments[0]
					new_packet.show2
					segments.append(new_packet)
				else:
					new_packet = segments[s-1].copy()
					del(new_packet[IP].chksum)
					del(new_packet[IP].len)
					del(new_packet[TCP].payload)
					new_packet[IP].id +=1
					new_packet[TCP].seq = new_packet[TCP].seq + self.segsize
					new_packet[TCP].payload = split_segments[s]
					print new_packet[TCP].seq
					new_packet[TCP].flags="PA"
					new_packet.show2
					segments.append(new_packet)
		if (segments):
			return segments

		else:
			return p

	def setSegmentSize(self, segsize):
		self.segsize = int(segsize)

main()
