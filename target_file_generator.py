#!/usr/bin/python
_author_ = 'tarah'
#Simple script to generate target text files with IPv4 address ranges. Commonly used for nmap, unicorn, onetwopunch, and other offensive security enumeration tools.
#Complain to me on Twitter at @tarah or at tarah.org. Or don't. Whichever. 
#Help others by improving this script (my god, error handling ***IS*** a thing!) at @tarahmarie on Github. 

import argparse
from ipaddress import IPv4Address, IPv4Network
from itertools import chain, count
import re

LINE_WRITE_GROUPING = 10

class CIDR_IP_generator:
    prefix = ''
    beginning = 0
    cidr = '/24'
    end = None
    num_addresses = 0

    def __init__(self, prefix, cidr='/24', beginning=0, end=None):
        self.prefix = prefix
        self.beginning = beginning

        if end:
            self.end = end

        self.cidr = cidr

    def use_cidr(self):
        return None == self.end

    def get_zero(self, address):
        zeroth = '%s.0'.decode('utf-8') % self.prefix
        return iter((IPv4Address(zeroth),))

    def get_last(self, address):
        zeroth = '%s.%d'.decode('utf-8') % (self.prefix, self.num_addresses-1)
        return iter((IPv4Address(zeroth),))

    def add_zero(self, address):
        """
        >>> yes_because_0 = CIDR_IP_generator(None, None)
        >>> yes_because_0.add_zero('1.1.1.0')
        True
        >>> yes_because_cidr = CIDR_IP_generator(None, None)
        >>> yes_because_cidr.add_zero('1.1.1.0/24')
        True
        """
        if self.use_cidr():
            return True
        return 0 == int(address.split('.')[-1])

    def generate(self):
        """
        >>> generator1 = CIDR_IP_generator('1.1.1', cidr='0/24')
        >>> addresses = generator1.generate()
        >>> str(next(addresses).exploded)
        '1.1.1.0'
        >>> str(next(addresses).exploded)
        '1.1.1.1'
        >>> str([next(addresses) for x in range(0, 250)][-1].exploded)
        '1.1.1.251'
        >>> generator2 = CIDR_IP_generator('10.254.0', cidr='0/16')
        >>> addresses = generator2.generate()
        >>> str(next(addresses).exploded)
        '10.254.0.0'
        >>> str(next(addresses).exploded)
        '10.254.0.1'
        """
        compressed = '%s.%s' % (self.prefix, self.cidr)
        utf_string = compressed.decode('utf-8')
        network = IPv4Network(utf_string)
        self.num_addresses = network.num_addresses
        if self.add_zero:
            zeroth = self.get_zero(compressed)
            last = self.get_last(compressed)
            return chain(zeroth, network.hosts(), last)
        return network.hosts()

    def write(self, filename, host_iterator):
        start = 0
        counter = count(start, LINE_WRITE_GROUPING)

        with open(filename, 'a+') as f:
            limit = counter.next()
            while limit <= self.num_addresses:
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

        print "Successfully created a file named " + filename + " here, with 256 IP addresses and your specified octets."

cidr_list = ['/%d' % x for x in range(1, 32)]

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

    # parser.add_argument("-b", "--begin",
    #                     dest="begin",
    #                     type=int,
    #                     required=False,
    #                     default=0,
    #                     help='beginning address of fourth octet')

    # parser.add_argument("-e", "--end",
    #                     dest="end",
    #                     type=int,
    #                     required=False,
    #                     help='ending address of fourth octet')

    parser.add_argument("-c", "--cidr",
                        dest="cidr",
                        choices=cidr_list,
                        required=False,
                        default="0/24",
                        help='cidr to generate')

    args = parser.parse_args()
    prefix = '.'.join(str(octet) for octet in args.octet)

    generator = CIDR_IP_generator(prefix=prefix, cidr=args.cidr)
    hosts = generator.generate()
    generator.write(args.output_file, hosts)

if "__main__" == __name__:
    main()
