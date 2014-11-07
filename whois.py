#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IPv4 Whois data collection and analysis tool

Usage:
    ./whois.py collect <elastic_search_url> <index_name> <doc_name>
                       [--sleep_min=<n>] [--sleep_max=<n>] [--threads=<n>]
    ./whois.py stats   <elastic_search_url> <index_name>
    ./whois.py test
    ./whois.py (-h | --help)

Options:
    -h, --help         Show this screen and exit.
    --sleep_min=<n>    Least number of seconds to sleep for [Default: 1]
    --sleep_max=<n>    Most number of seconds to sleep for [Default: 5]
    --threads=<n>      Number of threads [Default: 8]

Examples:

    ./whois.py collect http://127.0.0.1:9200/ netblocks netblock
    ./whois.py stats http://127.0.0.1:9200/ netblocks

License:

The MIT License (MIT)

Copyright (c) 2014 Mark Litwintschik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import json
from random import randint
import socket
import struct
import sys

from docopt import docopt
import ipcalc
from ipwhois import IPWhois
import gevent
from pyelasticsearch import ElasticSearch
from pyelasticsearch.exceptions import \
     ElasticHttpError, ElasticHttpNotFoundError
import requests


def ip2long(ip):
        """
        Convert IPv4 address in string format into an integer

        :param str ip: ipv4 address

        :return: ipv4 address
        :rtype: integer
        """
        packed_ip = socket.inet_aton(ip)
        return struct.unpack("!L", packed_ip)[0]


def get_next_ip(ip_address):
    """
    :param str ip_address: ipv4 address

    :return: next ipv4 address
    :rtype: str

    >>> get_next_ip('0.0.0.0')
    '0.0.0.1'

    >>> get_next_ip('24.24.24.24')
    '24.24.24.25'

    >>> get_next_ip('24.24.255.255')
    '24.25.0.0'

    >>> get_next_ip('255.255.255.255') is None
    True
    """
    assert ip_address.count('.') == 3, \
           'Must be an IPv4 address in str representation'

    if ip_address == '255.255.255.255':
        return None

    try:
        return socket.inet_ntoa(struct.pack('!L', ip2long(ip_address) + 1))
    except Exception, error:
        print 'Unable to get next IP for %s' % ip_address
        raise error


def get_netrange_end(asn_cidr):
    """
    :param str asn_cidr: ASN CIDR

    :return: ipv4 address of last IP in netrange
    :rtype: str
    """
    try:
        last_in_netrange = \
            ip2long(str(ipcalc.Network(asn_cidr).host_first())) + \
            ipcalc.Network(asn_cidr).size() - 2
    except ValueError, error:
        print 'Issue calculating size of %s network' % asn_cidr
        raise error

    return socket.inet_ntoa(struct.pack('!L', last_in_netrange))


def get_next_undefined_address(ip):
    """
    Get the next non-private IPv4 address if the address sent is private

    :param str ip: IPv4 address

    :return: ipv4 address of net non-private address
    :rtype: str

    >>> get_next_undefined_address('0.0.0.0')
    '1.0.0.0'

    >>> get_next_undefined_address('24.24.24.24')
    '24.24.24.24'

    >>> get_next_undefined_address('127.0.0.1')
    '128.0.0.0'

    >>> get_next_undefined_address('255.255.255.256') is None
    True
    """
    try:
        # Should weed out many invalid IP addresses
        ipcalc.Network(ip)
    except ValueError, error:
        return None

    defined_networks = (
        '0.0.0.0/8',
        '10.0.0.0/8',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '192.88.99.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
        '255.255.255.255/32',
    )

    for network_cidr in defined_networks:
        if ip in ipcalc.Network(network_cidr):
            return get_next_ip(get_netrange_end(network_cidr))

    return ip


def break_up_ipv4_address_space(num_threads=8):
    """
    >>> break_up_ipv4_address_space() == \
     [('0.0.0.0', '31.255.255.255'), ('32.0.0.0', '63.255.255.255'),\
     ('64.0.0.0', '95.255.255.255'), ('96.0.0.0', '127.255.255.255'),\
     ('128.0.0.0', '159.255.255.255'), ('160.0.0.0', '191.255.255.255'),\
     ('192.0.0.0', '223.255.255.255'), ('224.0.0.0', '255.255.255.255')]
    True
    """
    ranges = []

    multiplier = 256 / num_threads

    for marker in range(0, num_threads):
        starting_class_a = (marker * multiplier)
        ending_class_a = ((marker + 1) * multiplier) - 1
        ranges.append(('%d.0.0.0' % starting_class_a,
                       '%d.255.255.255' % ending_class_a))

    return ranges


def get_netranges(starting_ip='1.0.0.0',
                  last_ip='2.0.0.0',
                  elastic_search_url='http://127.0.0.1:9200/',
                  index_name='netblocks',
                  doc_name='netblock', sleep_min=1, sleep_max=5):
    connection = ElasticSearch(elastic_search_url)
    current_ip = starting_ip

    while True:
        # See if we've finished the range of work
        if ip2long(current_ip) > ip2long(last_ip):
            return

        current_ip = get_next_undefined_address(current_ip)

        if current_ip == None: # No more undefined ip addresses
            return

        print current_ip

        try:
            whois_resp = IPWhois(current_ip).lookup_rws()
        except Exception as error:
            """
            If a message like: 'STDERR: getaddrinfo(whois.apnic.net): Name or
            service not known' appears' then print it out and try the next
            IP address.
            """
            print type(error), error
            current_ip = get_next_ip(current_ip)

            if current_ip is None:
                return # No more undefined ip addresses
            gevent.sleep(randint(sleep_min, sleep_max))
            continue

        if 'asn_cidr' in whois_resp and \
            whois_resp['asn_cidr'] is not None and \
            whois_resp['asn_cidr'].count('.') == 3:
            last_netrange_ip = get_netrange_end(whois_resp['asn_cidr'])
        else:
            try:
                last_netrange_ip = \
                    whois_resp['nets'][0]['range'].split('-')[-1].strip()
                assert last_netrange_ip.count('.') == 3
            except:
                # No match found for n + 192.0.1.0.
                print 'Missing ASN CIDR in whois resp: %s' %  whois_resp
                current_ip = get_next_ip(current_ip)

                if current_ip is None:
                    return # No more undefined ip addresses

                gevent.sleep(randint(sleep_min, sleep_max))
                continue

        assert last_netrange_ip is not None and \
               last_netrange_ip.count('.') == 3, \
               'Unable to find last netrange ip for %s: %s' % (current_ip,
                                                               whois_resp)

        # Save current_ip and whois_resp
        entry = {
            'netblock_start': current_ip,
            'netblock_end': last_netrange_ip,
            'block_size': ip2long(last_netrange_ip) - ip2long(current_ip) + 1,
            'whois': json.dumps(whois_resp),
        }

        keys = ('cidr', 'name', 'handle', 'range', 'description',
                'country', 'state', 'city', 'address', 'postal_code',
                'abuse_emails', 'tech_emails', 'misc_emails', 'created',
                'updated')

        for _key in keys:
            entry[_key] = str(whois_resp['nets'][0][_key]) \
                          if _key in whois_resp['nets'][0] and \
                             whois_resp['nets'][0][_key] else None

            if _key == 'city' and entry[_key] and ' ' in entry[_key]:
                entry[_key] = entry[_key].replace(' ', '_')

        try:
            connection.index(index_name, doc_name, entry)
        except ElasticHttpError, error:
            print 'At %s. Unable to save record: %s' % (current_ip, entry)
            raise error

        current_ip = get_next_ip(last_netrange_ip)

        if current_ip is None:
            return # No more undefined ip addresses

        gevent.sleep(randint(sleep_min, sleep_max))


def stats(elastic_search_url, index_name, doc_name):
    fields = ('country', 'city')
    url = '%s/%s/_search?fields=aggregations' % (elastic_search_url, index_name)

    for field in fields:
        data = {
            "aggs": {
                field: {
                    "terms": {
                        "field": field,
                        "order": {"total_ips": "desc"}
                    },
                    "aggs": {
                        "total_ips": {"sum": {"field": "block_size"}}
                    }
                }
            }
        }
        resp = requests.get(url, data=json.dumps(data))
        assert resp.status_code == 200, \
            'Did not get HTTP 200 back: %s' % resp.status_code
        _stats = json.loads(resp.content)["aggregations"][field]["buckets"]
        _stats = {stat['key']: int(stat['total_ips']['value'])
                  for stat in _stats}

        print 'Top 10 netblock locations by %s' % field
        for _key in sorted(_stats, key=_stats.get, reverse=True):
            print "{:14,d}".format(_stats[_key]), _key.replace('_', ' ')
        print


def main(argv):
    """
    :param dict argv: command line arguments
    """
    opt = docopt(__doc__, argv)

    if opt['collect']:
        sleep_min = int(opt['--sleep_min']) \
                    if opt['--sleep_min'] is not None else randint(1, 5)
        sleep_max = int(opt['--sleep_max']) \
                    if opt['--sleep_max'] is not None else randint(1, 5)

        num_threads = int(opt['--threads'])

        if sleep_min > sleep_max:
            sleep_min, sleep_max = sleep_max, sleep_min

        threads = [gevent.spawn(get_netranges, starting_id, ending_ip,
                   opt['<elastic_search_url>'], opt['<index_name>'],
                   opt['<doc_name>'], sleep_min, sleep_max)
                   for starting_id, ending_ip in
                   break_up_ipv4_address_space(num_threads)]

        gevent.joinall(threads)

    if opt['stats']:
        stats(opt['<elastic_search_url>'],
              opt['<index_name>'],
              opt['<doc_name>'])

    if opt['test']:
        import doctest
        doctest.testmod()


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        pass
