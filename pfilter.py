import sys
import re
import binascii
import base64
import codecs

DEBUG = 1



class Packet():    
    def __init__(self, ip_protocol, scr_ip, src_port, dst_ip, dst_port):
        self.ip_protocol = ip_protocol
        self.src_ip = src_ip
        self.src_pot = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

def processPacket(pack):
    with open(pack, "rb") as file:
        for line in file:
            #stuff = base64.standard_b64decode(line)
            stuff = line.decode('utf-8')
            print(stuff)
            
    

def getRules(filter):
    # Read in rules file
    with open(filter, "r") as file:
        rules = file.readlines()
        print(rules)
        file.close()
        return rules

def evaluate(rules):
    for rule in rules:
        Rule()
        rule_split = rule.split()
        print(rule_split)
        #if (rule_split[0] == "allow"):
            
            
        
def main():
    filter_file = sys.argv[1]
    #if (len(sys.argv) != 3):
     #   print("Usage: pfilter <filter> <packet>")
      #  sys.exit(-1)
    packet_file = sys.argv[2]
    rules = getRules(filter_file)
    print(rules)
    processPacket(packet_file)
   
    
  
    

main()