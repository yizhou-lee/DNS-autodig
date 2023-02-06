#!/usr/bin/python3

import sys, socket
from datetime import datetime
from dnslib import DNSRecord

# Default hardcoded name and address of root NS
ROOTNS_DN = "f.root-servers.net."
ROOTNS_IN_ADDR = "192.5.5.241"
ERROR_NAME = "Error name"
ERROR_IP = "Error ip"

# Create a client socket on which to send requests to other DNS servers
cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Read name to be resolved from stdin
if len(sys.argv) < 2:
  print("usage: {} [-r <DNS_root_IP_address>] <names_to_resolve>".format(sys.argv[0]))
  sys.exit()
  
# Support specification of custom DNS root IP address via option -r
if sys.argv[1] == "-r":
  dns_root_addr = sys.argv[2]
  name_to_resolve = sys.argv[3:]
else:
  dns_root_addr = ROOTNS_IN_ADDR
  name_to_resolve = sys.argv[1:]

local_cache = []
dig_process = []

def cache_store(name, ttl, address, rtype):
  # record the time of storing cache
  create_time = datetime.now()
  create_time = create_time.strftime("%Y-%m-%d %H:%M:%S")
  create_time = datetime.strptime(create_time, r"%Y-%m-%d %H:%M:%S")
  local_cache.append({ "name": name, "ttl": ttl, "address": address, "create_time": create_time, "rtype": rtype })

def match_cache(name, address):
  flag = 0  # check if find the address in the cache
  address = dns_root_addr
  name_len = 0
  # Record the time of checking cache
  check_time = datetime.now()
  check_time = check_time.strftime("%Y-%m-%d %H:%M:%S")
  check_time = datetime.strptime(check_time, r"%Y-%m-%d %H:%M:%S")

  for record in local_cache:
    time_diff = check_time - record["create_time"]
    time_spent = time_diff.total_seconds()
    # Check if the record has been expired
    if time_spent > record["ttl"]:
      local_cache.remove(record)  # remove the expired record
    else:
      if record["name"] == name:
        if record["rtype"] == "A":
          address = record["address"]
          flag = 1
        else:
          address = record["address"]
      elif name.endswith('.' + record["name"]) and len(record["name"]) > name_len:
        name_len = len(record["name"])
        address = record["address"]
  return address, flag

def find_dns_ip(name, address):
  # Create a DNS request packet
  try:
    query = DNSRecord.question(name)
  except:
    return ERROR_NAME
  
  packet = query.pack()
  # Search the cache
  address, flag = match_cache(name, address)
  if flag == 1:
    return address

  cs.sendto(packet,(address,53))
  (response, _) = cs.recvfrom(512)
  # Record the dig process
  dig_process.append("dig {} +norecurse @{}".format(name, address))
  # print("dig {} +norecurse @{}".format(name, address))
  parsed_response = DNSRecord.parse(response)
  # print("{}\n".format(parsed_response))
  parsed_answer = parsed_response.get_a()
  parsed_authorities = parsed_response.auth
  parsed_additionals = parsed_response.ar

  if parsed_answer.rdata != None:
    if parsed_answer.rtype != 1:  # rtype != "A"
      cname = str(parsed_answer.rdata)
      ip_address = find_dns_ip(cname, address)
      cache_store(str(parsed_answer.rname), parsed_answer.ttl, ip_address, "A")
      return ip_address
    else:
      result_ip = str(parsed_answer.rdata)
      cache_store(str(parsed_answer.rname), parsed_answer.ttl, result_ip, "A")
      return result_ip

  if len(parsed_authorities) != 0:
    if parsed_authorities[0].rtype != 2:  # rtype != "NS"
      return ERROR_IP  # the IP is not exist
    # Find the additional record with the same name and rtype is A
    if len(parsed_additionals) != 0:
      for record in parsed_authorities:
        ar_list = list(filter(lambda x: x.rname == str(record.rdata) and x.rtype == 1, parsed_additionals))
        if len(ar_list) != 0:
          ar_result = ar_list[0]
          ip_address = str(ar_result.rdata)
          cache_store(str(record.rname), record.ttl, ip_address, "NS")
          break
    else:
      auth_result = parsed_authorities[0]
      auth_name = str(auth_result.rdata)
      ip_address = find_dns_ip(auth_name, address)
      cache_store(str(auth_result.rname), auth_result.ttl, ip_address, "NS")
  else: 
    return ERROR_IP

  return find_dns_ip(name, ip_address)
    

# The start of the program
for i in name_to_resolve:
  if not i.endswith('.'):
    i = i + '.'
  ans_ip = find_dns_ip(i, dns_root_addr)
  if ans_ip == ERROR_IP:
    print("The ip of {} cannot be found.".format(i))
    for dig_record in dig_process:
      print(dig_record)
    print("")
  elif ans_ip ==ERROR_NAME:
    print("{} is a wrong ip name.".format(i))
    for dig_record in dig_process:
      print(dig_record)
    print("")
  else:
    print("Resolved name {} to {}".format(i, ans_ip))
    for dig_record in dig_process:
      print(dig_record)
    print("")
  dig_process = []