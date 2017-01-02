#!/usr/bin/env python3
import re, dns.resolver
import json
from sys import getsizeof, argv


class SPFlatten:
   def __init__(self, root_domain='google.com', verbose=False, json_output=False):
      self.root_domain = root_domain
      self.spf_ip_list = []
      self.spf_nonflat_mechanisms = []
      self.all_mechanism = ''
      self.split_records = {}
      self.verbose = verbose
      self.json_output = json_output
      self.output = lambda *args: print(*args) if self.verbose else None

      # Run Class
      self.flatten()
      self.structure_spf()

      # Reconcile/Structure records.
      self.spf_records = { x:y+' ~all' for x,y in self.split_records.items() if '~all' not in y }
      self.spf_records[root_domain] = self.split_records[root_domain]
      self.add_includes()
   
   def parse_mechanism(self, mechanism, domain):
   # Parse the given mechansim, and dispatch it accordintly
      if re.match(r'^a$', mechanism):
         self.convert_domain_to_ipv4(domain)
      elif re.match(r'^mx$', mechanism):
         self.convert_mx_to_ipv4(domain)
      elif re.match(r'^a:.*$', mechanism):
         match = re.match(r'^a:(.*)$', mechanism)
         self.convert_domain_to_ipv4(match.group(1))
      elif re.match(r'^ip4:.*$', mechanism):
         match = re.match(r'^ip4:(.*)$', mechanism)
         self.output("IPv4 address found for", domain, ":", match.group(1))
         self.spf_ip_list.append(match.group(1))
      elif re.match(r'^ip6:.*$', mechanism):
         match = re.match(r'^ip6:(.*)$', mechanism)
         self.output("IPv6 address found for", domain, ":", match.group(1))
         self.spf_ip_list.append(match.group(1))
      elif re.match(r'^ptr.*$', mechanism):
         self.output("PTR found for", domain, ":", mechanism)
         self.spf_nonflat_mechanisms.append(mechanism)
      elif re.match(r'^exists:$', mechanism):
         self.output("Exists found for", domain, ":", mechanism)
         self.spf_nonflat_mechanisms.append(mechanism)
      elif re.match(r'^redirect:$', mechanism):
         self.output("Redirect found for", domain, ":", mechanism)
         self.spf_nonflat_mechanisms.append(mechanism)
      elif re.match(r'^exp:$', mechanism):
         self.output("EXP found for", domain, ":", mechanism)
         self.spf_nonflat_mechanisms.append(mechanism)
      elif re.match(r'^.all$', mechanism):
         if domain == self.root_domain:
            match = re.match(r'^(.all)$', mechanism)
            self.output("All found for", domain, ":", match.group(1))
            self.all_mechanism = " " + str(match.group(1))
      elif re.match(r'^include:.*$', mechanism):
         match = re.match(r'^include:(.*)', mechanism)
         self.flatten_spf(match.group(1)) # recursion

   def convert_domain_to_ipv4(self, domain):
   # Convert A/AAAA records to IPs and adds them to the SPF master list
      a_records = []
      aaaa_records = []

      try:
         a_records = dns.resolver.query(domain, "A")
         for ip in a_records:
            self.output("A record for", domain, ":", str(ip))
            self.spf_ip_list.append(str(ip))
      except dns.exception.DNSException:
         pass

      try:
         aaaa_records = dns.resolver.query(domain, "AAAA")
         for ip in aaaa_records:
            self.output("A record for", domain, ":", str(ip))
            self.spf_ip_list.append(str(ip))
      except dns.exception.DNSException:
         pass
   
   def convert_mx_to_ipv4(self, domain):
   # Convert MX records to IPs and adds them to the SPF master list
      try:
         mx_records = dns.resolver.query(domain, "MX")
      except dns.exception.DNSException:
         return

      for record in mx_records:
         mx = str(record).split(' ')
         self.output("MX record found for ", domain, ": ", mx[1])
         self.convert_domain_to_ipv4(mx[1])  
   
   def flatten_spf(self, domain):
   # Recursively flatten the SPF record for the specified domain
      self.output("--- Flattening:", domain, "---")
      try:
         txt_records = dns.resolver.query(domain, "TXT")
      except dns.exception.DNSException:
         self.output("No TXT records for:", domain)
         return

      for record in txt_records:
         self.output("TXT record for:", domain, ":", str(record))
         fields = str(record)[1:-1].split(' ')

         if re.match(r'v=spf1', fields[0]):
            for field in fields:
               self.parse_mechanism(field, domain)

   def flatten(self):
   # Creates the initial flat SPF record with all the IP addresses.
      self.flatten_spf(self.root_domain)

      dedupe_spf_ip_list = list(set(self.spf_ip_list))
      
      self.raw_flat_spf = "v=spfv1"
      
      ip_string = lambda ip: " ip6:%s" % ip if re.match(r'.*:.*', ip) else " ip4:%s" % ip
      for ip in dedupe_spf_ip_list:
         self.raw_flat_spf += ip_string(ip)

      for mechanism in self.spf_nonflat_mechanisms: 
         self.raw_flat_spf += mechanism

      self.raw_flat_spf += self.all_mechanism
      self.split_records[self.root_domain] = self.raw_flat_spf

   def structure_spf(self, count=1, block_limit=450):
   # Ass UDP packets can only be 512 bytes, splits the flattened spf record into blocks smaller than the block limit
      if not any([getsizeof(record) > block_limit for x, record in self.split_records.items() ]):
         return
      for domain, spf_record in dict(self.split_records).items():
         while getsizeof(spf_record) > block_limit:
            ip_list = spf_record.split(' ')
            new_domain_record = 'spf%s.%s' % (count, self.root_domain)

            if new_domain_record not in self.split_records.keys():
               self.split_records[new_domain_record] = 'v=spf1'   
            self.split_records[new_domain_record] += ' %s' % ip_list.pop(len(ip_list)-2)
            
            spf_record = ' '.join(ip_list)
            self.split_records[domain] = spf_record

      self.structure_spf(count=count+1) # <<--- Recursively reduce the size of each record
      return

   def add_includes(self):
   # Adds the include:<ip> to each record where needed.
      include = lambda r_list, value: r_list.insert(len(r_list)-1, value)
      for domain, record in self.spf_records.items():
         record_list = record.split(' ')
         if 'spf' in domain.split('.')[0]:
            record_num = int(domain.split('.')[0][-1:])
            next_record = 'spf%s.%s' % (record_num+1,self.root_domain)
            if next_record in self.spf_records.keys():
               include(record_list, 'include:%s' % next_record)
         else: 
            next_record = 'include:spf1.%s' % self.root_domain
            if len(self.spf_records.keys()) > 1:
               include(record_list, next_record)
         self.spf_records[domain] = ' '.join(record_list)
      return

   def Outputs(self):
   # Prints out SPF record outputs
      if self.json_output:
         print(json.dumps(self.spf_records))
         return
      for domain, record in self.spf_records.items(): 
         print('\n%s:\n%s\n' % (domain, record))


if __name__ == "__main__":
   if len(argv) > 1:
      SPFlatten(
            root_domain=argv[1].replace('www.', ''),
            verbose=('-v' in argv),
            json_output=('-j' in argv)
         ).Outputs()
   else:
      print('\n Usage: %s [domain] [flags]\n\n-j\tjson output\n-v\tverbose output\n' % argv[0])