# send_report_to_es

## Summary

Send a puppet report to ElasticSearch.

Configuration is read from the file specified in the environment variable
`PUPPET_ES_CONFIG` (defaults to `/etc/puppet_es.conf`) and uses ConfigParser
syntax. A sample configuration file is included as
[`etc/puppet_es.conf.example`](etc/puppet_es.conf.example).

## Usage

### Command

~~~bash
send_report_to_es [-h|--help] <filename>
~~~

### Options

~~~
-h/--help   Show this help text and exit
~~~

### Parameters

~~~
filename    The JSON file for the report to load and send to ElasticSearch
~~~

## Configuring ElasticSearch

An example ElasticSearch template that supports the format this script uses can
be found at [`etc/puppet_template.json`](etc/puppet_template.json).
