import re
import dns.resolver
import boto3
from sys import getsizeof

# Set domain
domain = '<your domain here>'


class SPFlatten:

    def __init__(self, root_domain='cloudreach.com'):
        self.root_domain = root_domain
        self.spf_ip_list = []
        self.spf_nonflat_mechanisms = []
        self.all_mechanism = ''
        self.split_records = {}

        # Run Class
        self.flatten()
        self.structure_spf()

        # Reconcile/Structure records.
        self.spf_records = {x: y + ' ~all' for x,
                            y in self.split_records.items() if '~all' not in y}
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
            self.spf_ip_list.append(match.group(1))
        elif re.match(r'^ip6:.*$', mechanism):
            match = re.match(r'^ip6:(.*)$', mechanism)
            self.spf_ip_list.append(match.group(1))
        elif re.match(r'^ptr.*$', mechanism):
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^exists:$', mechanism):
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^redirect:$', mechanism):
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^exp:$', mechanism):
            self.spf_nonflat_mechanisms.append(mechanism)
        elif re.match(r'^.all$', mechanism):
            if domain == self.root_domain:
                match = re.match(r'^(.all)$', mechanism)
                self.all_mechanism = " " + str(match.group(1))
        elif re.match(r'^include:.*$', mechanism):
            match = re.match(r'^include:(.*)', mechanism)
            self.flatten_spf(match.group(1))  # recursion

    def convert_domain_to_ipv4(self, domain):
        # Convert A/AAAA records to IPs and adds them to the SPF master list
        a_records = []
        aaaa_records = []

        try:
            a_records = dns.resolver.query(domain, "A")
            for ip in a_records:
                self.spf_ip_list.append(str(ip))
        except dns.exception.DNSException:
            pass
        try:
            aaaa_records = dns.resolver.query(domain, "AAAA")
            for ip in aaaa_records:
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
            self.convert_domain_to_ipv4(mx[1])

    def flatten_spf(self, domain):
        # Recursively flatten the SPF record for the specified domain
        try:
            txt_records = dns.resolver.query(domain, "TXT")
        except dns.exception.DNSException:
            return
        for record in txt_records:
            fields = str(record)[1:-1].split(' ')
            if re.match(r'v=spf1', fields[0]):
                for field in fields:
                    self.parse_mechanism(field, domain)

    def ip_string(self, ip):
        # Used solely by the flatten mthod of this class.
        if re.match(r'.*:.*', ip):
            return " ip6:%s" % ip
        else:
            return " ip4:%s" % ip

    def flatten(self):
        # Creates the initial flat SPF record with all the IP addresses.
        self.flatten_spf(self.root_domain)
        dedupe_spf_ip_list = list(set(self.spf_ip_list))
        self.raw_flat_spf = "v=spfv1"

        for ip in dedupe_spf_ip_list:
            self.raw_flat_spf += self.ip_string(ip)

        for mechanism in self.spf_nonflat_mechanisms:
            self.raw_flat_spf += mechanism

        self.raw_flat_spf += self.all_mechanism
        self.split_records[self.root_domain] = self.raw_flat_spf

    def structure_spf(self, count=1, block_limit=450):
        # As UDP packets can only be 512 bytes, splits the flattened spf
        # record into blocks smaller than the block limit
        large_records = [
            getsizeof(record) > block_limit
            for x, record in self.split_records.items()
        ]
        if not any(large_records):
            return
        for domain, spf_record in dict(self.split_records).items():
            while getsizeof(spf_record) > block_limit:
                ip_list = spf_record.split(' ')
                new_domain_record = 'spf%s.%s' % (count, self.root_domain)

                if new_domain_record not in self.split_records.keys():
                    self.split_records[new_domain_record] = 'v=spf1'
                self.split_records[
                    new_domain_record] += ' %s' % ip_list.pop(len(ip_list) - 2)

                spf_record = ' '.join(ip_list)
                self.split_records[domain] = spf_record

        # <<--- Recursively reduce the size of each record
        self.structure_spf(count=count + 1)
        return

    def add_includes(self):
        # Adds the include:<ip> to each record where needed.
        def include(r_list, value):
            return r_list.insert(len(r_list) - 1, value)
        for domain, record in self.spf_records.items():
            record_list = record.split(' ')
            if 'spf' in domain.split('.')[0]:
                record_num = int(domain.split('.')[0][-1:])
                next_record = 'spf%s.%s' % (record_num + 1, self.root_domain)
                if next_record in self.spf_records.keys():
                    include(record_list, 'include:%s' % next_record)
            else:
                next_record = 'include:spf1.%s' % self.root_domain
                if len(self.spf_records.keys()) > 1:
                    include(record_list, next_record)
            self.spf_records[domain] = ' '.join(record_list)
        return

    def records(self):
        # returns a dict of records
        return {domain: record for domain, record in self.spf_records.items()}


def get_zone_id(domain):
    r53 = boto3.client('route53')
    print('INFO: Fetching Zone ID for %s' % domain)
    zones = r53.list_hosted_zones()['HostedZones']
    if domain in [zone['Name'].strip('.') for zone in zones]:
        return [
            zone['Id'].replace('/hostedzone/', '')
            for zone in zones
            if zone['Name'].strip('.') == domain
        ][0]
    print('ERROR: No Zone ID Found for ---> %s' % domain)
    return None


def handler(event, context):
    r53 = boto3.client('route53')
    spf = SPFlatten(root_domain=domain)
    txt_records = spf.records()

    for dom, record in txt_records.items():
        try:
            print('\nINFO: Setting SPF Record: %s' % dom)
            response = r53.change_resource_record_sets(
                HostedZoneId=get_zone_id(domain),
                ChangeBatch={
                    'Comment': 'SPF Flattening TXT record creation',
                    'Changes': [
                        {
                            'Action': 'UPSERT',
                            'ResourceRecordSet': {
                                'Name': dom,
                                'Type': 'TXT',
                                'TTL': 60,
                                'ResourceRecords': [
                                    {
                                        'Value': '\"%s\"' % record
                                    },
                                ],
                            }
                        },
                    ]
                }
            )
            print('INFO: HTTP Status Code --> %s' %
                  response['ResponseMetadata']['HTTPStatusCode'])
            print('INFO: RequestId --> %s\n' %
                  response['ResponseMetadata']['RequestId'])
        except Exception as e:
            print('ERROR: %s' % e)
            return (False, e)
    return True
