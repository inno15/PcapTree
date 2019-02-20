#! /usr/bin/env python
import subprocess
import datetime
import json
import os
import time
import argparse
from scapy.all import *
from capinfo import capinfos
import signal
import sys


#Global dictionary that contains the result of the analysis
resultdict = dict()
#variables that are needed to create one file per day of analysis
currentday = 0
# keeps track of the number of pcaps per day
pcapnumber = 0
currentmonth = 0
#starting time of execution
start_time = 0

def signal_handler(sig, frame):
	print('You pressed Ctrl+C! writing the partial output to file')
	write_output_file()
	sys.exit(0)

def addCapInfos(PcapPath):
	global resultdict
	#function that given name of the pcap gets the necessary information
	capinfo_dict = capinfos(PcapPath)
	if "avgpacketrate" not in  resultdict and "avgpacketsize" not in resultdict and "byterate" not in resultdict and "packetscount" not in resultdict:
		resultdict["avgpacketrate"] = capinfo_dict["avgpacketrate"]
		resultdict["avgpacketsize"] = capinfo_dict["avgpacketsize"]
		resultdict["byterate"] = capinfo_dict["byterate"]
		resultdict["packetscount"] = capinfo_dict["packetscount"]
	else:
		resultdict["avgpacketrate"] += capinfo_dict["avgpacketrate"]
		resultdict["avgpacketsize"] += capinfo_dict["avgpacketsize"]
		resultdict["byterate"] += capinfo_dict["byterate"]
		resultdict["packetscount"] += capinfo_dict["packetscount"]
	print "PcapInfos of " + PcapPath + " "
	print capinfo_dict

	return
#example of a Python generator
def get_packet_layers(packet):
    counter = 0
    packet_layers = ""
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            return packet_layers
        else:
        	packet_layers = packet_layers + " Layer" + str(counter) + ": " + layer.name
        counter += 1

def get_packet_src(packet):
	packet_src = ""

	try:
		packet_src = packet_src + packet[0].src

	except AttributeError as error:
		packet_src = packet_src + "NO layer 0 address - "

	try:
		packet_src = packet_src + " - " + packet[1].src

	except AttributeError as error:
		packet_src = packet_src + " - NO layer 1 address"


	return packet_src

def get_packet_dst(packet):
	packet_dst = ""

	try:
		packet_dst = packet_dst + packet[0].dst

	except AttributeError as error:
		packet_dst = packet_dst + "NO layer 0 address - "

	try:
		packet_dst = packet_dst + " - " + packet[1].dst

	except AttributeError as error:
		packet_dst = packet_dst + " - NO layer 1 address"


	return packet_dst

def write_output_file():
	global resultdict

	print resultdict
	#fix the averages of pcap infos
	resultdict["avgpacketrate"] /= pcapnumber
	resultdict["avgpacketsize"] /= pcapnumber
	resultdict["byterate"] /= pcapnumber
	
	elapsed_time = time.time() - start_time

	f= open("treeanalysis" + "_" + currentday + "_" + currentmonth + ".json","w+")
	out = json.dumps(resultdict, indent=1)
	print out
	print("--- %s minutes of execution ---" % (elapsed_time/60))
	f.write(out)
	f.close()

	#flush the result dictionary
	#Global dictionary that contains the result of the analysis
	resultdict.clear()




def parsePcapFile(file_path):

	global pcapnumber
	global currentday
	global currentmonth
	global resultdict

	pcapnumber +=1

	
	myreader= PcapReader(file_path)

	packet_timestamp = datetime.fromtimestamp(myreader.read_packet(1).time)
	pcap_day = str(packet_timestamp.day)
	pcap_month = str(packet_timestamp.month)


	if(currentday == 0):
		currentday = pcap_day
		currentmonth = pcap_month
	elif pcap_day != currentday:
		write_output_file()
		currentday = pcap_day
		currentmonth = pcap_month
		pcapnumber = 0

	addCapInfos(file_path)

	if "layers" not in  resultdict and "srcs" not in resultdict and "dsts" not in resultdict and "couples" not in resultdict:
		resultdict["layers"] = dict()
		resultdict["srcs"] = dict()
		resultdict["dsts"] = dict()
		resultdict["couples"] = dict()

	# get capinfos

	#i = 0	uncomment to test on little iterations
	#now the analysis can start
	for p in myreader:
		
		#if i<2000:
			#return uncomment to test 

			packet_layers=get_packet_layers(p)
			#adding the layer of the packet
			if packet_layers in resultdict["layers"]:
				resultdict["layers"][packet_layers] += 1
			else:
				resultdict["layers"][packet_layers] = 1
			#adding the srcs of a packet
			packet_src = get_packet_src(p)
			if packet_src not in resultdict["srcs"]:
				resultdict["srcs"][packet_src]=dict()
				resultdict["srcs"][packet_src][packet_layers]=1
			elif packet_layers not in resultdict["srcs"][packet_src]:
				resultdict["srcs"][packet_src][packet_layers]=1
			else:
				resultdict["srcs"][packet_src][packet_layers] += 1



			packet_dst = get_packet_dst(p)
			if packet_dst not in resultdict["dsts"]:
				resultdict["dsts"][packet_dst]=dict()
				resultdict["dsts"][packet_dst][packet_layers]=1
			elif packet_layers not in resultdict["dsts"][packet_dst]:
				resultdict["dsts"][packet_dst][packet_layers]=1
			else:
				resultdict["dsts"][packet_dst][packet_layers] += 1

			packet_couple = packet_src + " | " + packet_dst
			if packet_couple not in resultdict["couples"]:
				resultdict["couples"][packet_couple]=dict()
				resultdict["couples"][packet_couple][packet_layers]=1
			elif packet_layers not in resultdict["couples"][packet_couple]:
				resultdict["couples"][packet_couple][packet_layers]=1
			else:
				resultdict["couples"][packet_couple][packet_layers] += 1
		#i+=1




def main():
	global start_time

	#	Parser of argument inputs
	parser = argparse.ArgumentParser(description="This scripts analyzes a pcap extracting the analytics of the communication in a network divided per day \n the name of the files should follow this format [nameofthefile].pcap[numberofpcap] ")
	parser.add_argument("-d", help="directory that contains the pcaps to analyze", required=True)
	parser.add_argument("-z", action="store_true", help="add option to zip the pcap files after analyzing them. The compressed pcap is deleted. (at the moment this functionality requires 7zip)")
	args = parser.parse_args()

	signal.signal(signal.SIGINT, signal_handler)

	input_dir = args.d if (args.d[len(args.d)-1] == "/") else args.d+"/"

	start_time = time.time()
	pcap_file_list = list()

	for anyfilename in os.listdir(input_dir):
		if ".pcap" in anyfilename and ".zip" not in anyfilename :
			pcap_file_list.append(anyfilename)

	for filename in sorted(pcap_file_list, key=lambda a: int(a.split(".pcap")[1])):
		if ".pcap" in filename and ".zip" not in filename :
			print "analyzing file " + filename
			start_time = time.time()
			parsePcapFile(input_dir+filename)
			#the parsing of the pcap ends the file can be
			if args.z:
				print "Analysis finished on " + filename + " zipping it up"
				subprocess.Popen(["7z","a","-tzip",input_dir + filename.split(".pcap")[0] + "_"+ filename.split(".pcap")[1]+".zip", input_dir+filename, "-sdel"], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	write_output_file()


if __name__=="__main__":
	main()