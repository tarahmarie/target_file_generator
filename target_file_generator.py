#!/usr/bin/python
_author_ = 'tarah'
#Simple script to generate target text files with IPv4 address ranges. Commonly used for nmap, unicorn, onetwopunch, and other offensive security enumeration tools.
#Complain to me on Twitter at @tarah or at tarah.org. Or don't. Whichever. 
#Help others by improving this script (my god, error handling ***IS*** a thing!) at @tarahmarie on Github. 

import argparse
from ipaddress import IPv4Address, IPv4Network
from itertools import chain, count

LINE_WRITE_GROUPING = 10

class CIDR_IP_generator:
    prefix = ''
    cidr = 24
    num_addresses = 0

    def __init__(self, prefix, cidr=24):
        self.prefix = prefix
        self.cidr = cidr

    def get_zero(self, address):
        zeroth = '%s.0'.decode('utf-8') % self.prefix
        return iter((IPv4Address(zeroth),))

    def get_last(self, address):
        last = '%s.%d'.decode('utf-8') % (self.prefix, self.num_addresses-1)
        return iter((IPv4Address(last),))

    def generate(self):
        """
        >>> generator1 = CIDR_IP_generator('1.1.1', cidr=24)
        >>> addresses = generator1.generate()
        >>> str(next(addresses).exploded)
        '1.1.1.0'
        >>> str(next(addresses).exploded)
        '1.1.1.1'
        >>> str([next(addresses) for x in range(0, 250)][-1].exploded)
        '1.1.1.251'
        >>> generator2 = CIDR_IP_generator('10.254.0')
        >>> addresses = generator2.generate()
        >>> str(next(addresses).exploded)
        '10.254.0.0'
        >>> str(next(addresses).exploded)
        '10.254.0.1'
        """
        compressed = '%s.0/%s' % (self.prefix, self.cidr)
        utf_string = compressed.decode('utf-8')
        network = IPv4Network(utf_string)
        self.num_addresses = network.num_addresses
        zeroth = self.get_zero(compressed)
        last = self.get_last(compressed)
        return chain(zeroth, network.hosts(), last)

    def write(self, filename, host_iterator):
        """
        >>> generator1 = CIDR_IP_generator('1.1.1', cidr=24)
        >>> lines = generator1.generate()
        >>> generator1.write('.test.out', lines)
        >>> sum(1 for line in open('.test.out'))
        256
        """
        start = 0
        counter = count(start, LINE_WRITE_GROUPING)

        open(filename, 'w').close()

        with open(filename, 'a+') as f:
            limit = counter.next()
            while limit < self.num_addresses:
                lines = []
                for x in range(LINE_WRITE_GROUPING):
                    try:
                        host = host_iterator.next()
                        line = '%s\n' % str(host.exploded)
                        lines.append(line)
                    except:
                        break
                f.writelines(lines)
                limit = counter.next()


cidr_list = [x for x in range(1, 25)]

def main():
    parser = argparse.ArgumentParser(description='This script generates a custom text file of 256 IPv4 addresses for use as target files for nmap, onetwopunch, and other iterators and enumerators.')

    parser.add_argument("-f", "--output-file",
                        dest="output_file",
                        required=True,
                        help="output file name")

    parser.add_argument("-o", "--octets",
                        dest="octet",
                        type=int,
                        nargs=3,
                        required=True,
                        help='first 3 octets of the address')

    parser.add_argument("-c", "--cidr",
                        dest="cidr",
                        choices=cidr_list,
                        required=False,
                        type=int,
                        default=24,
                        help='cidr to generate')

    args = parser.parse_args()
    prefix = '.'.join(str(octet) for octet in args.octet)

    generator = CIDR_IP_generator(prefix=prefix, cidr=args.cidr)
    hosts = generator.generate()
    generator.write(args.output_file, hosts)
    print
    f"Successfully created a file named {args.output_file} here, with {generator.num_addresses:d} IP addresses and your specified octets."

if "__main__" == __name__:
    main()
