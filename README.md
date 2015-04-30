IPv4 Whois data collection and analysis tool
============================================

[![Build Status](https://travis-ci.org/marklit/whois.svg?branch=master)](https://travis-ci.org/marklit/whois)
[![Coverage Status](https://coveralls.io/repos/marklit/whois/badge.png)](https://coveralls.io/r/marklit/whois)
[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](http://opensource.org/licenses/MIT)

Collects WHOIS details for every IPv4 netblock. Reports supported via Elasticsearch.

Please see this [blog post](http://tech.marksblogg.com/all-ipv4-whois-records.html) detailing it's structure and behaviours.

```
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
```

License
=======
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
