#!/usr/bin/python3

import sys, socket
from dnslib import DNSRecord

# Default hardcoded name and address of root NS
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"

# Create a client socket on which to send requests to other DNS servers
cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Read name to be resolved from stdin
print(sys.argv)
if len(sys.argv) < 2:
  print("usage: {} [-r <DNS_root_IP_address>] <names_to_resolve>".format(sys.argv[0]))
  sys.exit()
# TODO: support specification of custom DNS root IP address via option -r

# name_to_resolve = sys.argv[1]
name_to_resolve = "google.com"

# Query the DNS root for the name to be resolved 
# TODO: generalize the following code so that
# - it queries the right name servers to obtain the IP corresponding to the input name
# - it supports the resolution of multiple names 

# Create a DNS Request Packet
query = DNSRecord.question(name_to_resolve)
packet = query.pack()
cs.sendto(packet,(ROOTNS_IN_ADDR,53))

# Receive the reply from the DNS root
(response, _) = cs.recvfrom(512)

# Example of how to parse the response packet using dnslib 
# TODO: eventually remove the following prints
parsed_response = DNSRecord.parse(response)
print("\nFull response: \n{}".format(parsed_response))

parsed_question = parsed_response.q
print("\nQuestion in the response: \n{}".format(parsed_question))

parsed_answer = parsed_response.get_a()
if parsed_answer.rdata != None:
  print("\nAnswer in the response: \n{}".format(parsed_answer))

parsed_authorities = parsed_response.auth
print("\nAuthority RRs in the response: \n{}".format(parsed_authorities))

parsed_additionals = parsed_response.ar
print("\nAdditional RRs in the response: \n{}".format(parsed_additionals))

# TODO: Process DNS response, and print output in the format specified in the handout

