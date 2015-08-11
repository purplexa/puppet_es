"""
send_report_to_es

Send a puppet report to ElasticSearch.

Configuration is read from the file specified in the environment variable
`PUPPET_ES_CONFIG` (defaults to /etc/puppet_es.conf) and uses ConfigParser
syntax. A sample configuration file is included as etc/puppet_es.conf.example.

Usage:
    send_report_to_es [-h|--help] <filename>

Options:
    -h/--help   Show this help text and exit

Parameters:
    filename    The JSON file for the report to load and send to ElasticSearch
"""
from __future__ import print_function
import ConfigParser
from contextlib import contextmanager
import json
import logging
import logging.handlers
import sys
import os

from elasticsearch import Elasticsearch
import elasticsearch.helpers


logger = logging.getLogger(__name__)


class InvalidReport(ValueError):
    pass


def prep_logging(conf):
    logger.setLevel(getattr(logging, conf.get('level', 'WARNING')))
    use_syslog = conf.get('syslog', True)
    logfile = conf.get('file')
    stderr = conf.get('stderr', False)
    if not use_syslog:
        logger.removeHandler(syslog_handler)
    if logfile:
        logger.addHandler(logging.FileHandler(logfile))
    if stderr:
        logger.addHandler(logging.StreamHandler())
    if use_syslog:
        logger.info('Logging to syslog')
    if logfile:
        logger.info('Logging to file {}'.format(logfile))
    if stderr:
        logger.info('Logging to stderr')


def help():
    print(__doc__)
    exit(0)


def parse_json(filename):
    try:
        with open(filename) as f:
            return json.load(f)
    except IOError as e:
        msg = 'Could not open {0} for reading: {1}'.format(filename, e)
        logger.exception(msg)
        raise
    except ValueError as e:
        msg = 'Could not parse JSON in {0}: {1}'.format(filename, e)
        logger.exception(msg)
        raise


def get_conf():
    conf_file = os.environ.get('PUPPET_ES_CONFIG', '/etc/puppet_es.conf')
    conf = ConfigParser.RawConfigParser()
    conf.read(conf_file)
    result = dict()
    for section in conf.sections():
        result[section] = dict()
    with required_setting('elasticsearch', 'host'):
        result['elasticsearch']['host'] = conf.get('elasticsearch', 'host')
    with required_setting('elasticsearch', 'host'):
        try:
            result['elasticsearch']['port'] = conf.getint('elasticsearch', 'port')
        except ValueError as e:
            msg = 'Option "port" in section "elasticsearch" in config file should be an integer.'
            logger.exception(msg)
            raise
    try:
        result['logging']['level'] = conf.get('logging', 'level')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        # This is not a required parameter.
        pass
    try:
        result['logging']['syslog'] = conf.getboolean('logging', 'syslog')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        # This is not a required parameter.
        pass
    except ValueError as e:
        msg = 'Option "syslog" in section "logging" in config file should be a boolean'
        logger.exception(msg)
        raise
    try:
        result['logging']['stderr'] = conf.getboolean('logging', 'stderr')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        # This is not a required parameter.
        pass
    except ValueError as e:
        msg = 'Option "stderr" in section "logging" in config file should be a boolean'
        logger.exception(msg)
        raise
    try:
        result['logging']['file'] = conf.get('logging', 'file')
    except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
        # This is not a required parameter.
        pass
    return result


@contextmanager
def required_setting(section, option):
    try:
        yield
    except ConfigParser.NoSectionError as e:
        msg = 'Section "{0}" in config file is required: {1}'.format(section, e)
        logger.exception(msg)
        raise
    except ConfigParser.NoOptionError as e:
        msg = ('Option "{0}" in section "{1}" in config file is required: {2}'.format(option, section, e))
        logger.exception(msg)
        raise


def prep_report(source):
    result = dict()
    # We want the values for these keys on the top-level object.
    for key in ['transaction_uuid', 'host', 'time', 'configuration_version',
                'status', 'environment']:
        result[key] = source[key]
    # Below, we want to pull out certain metrics and make them top-level
    # fields because ElasticSearch likes that better.

    # We want the counts for all the resource statuses.
    for k, v in {v[0]: v[2] for v in source['metrics']['resources']['values']}.iteritems():
        result['{}_resources'.format(k)] = v
    # We want the counts for all the event statuses.
    for k, v in {v[0]: v[2] for v in source['metrics']['events']['values']}.iteritems():
        result['{}_events'.format(k)] = v
    # We only want the global timing metrics, not the per-resource-type ones.
    times = {v[0]: v[2] for v in source['metrics']['time']['values']}
    for key in ['config_retrieval', 'total']:
        result['{}_time'.format(key)] = times[key]
    # There's only a single changes count value.
    result['total_changes'] = source['metrics']['changes']['values'][0][2]
    return result

def prep_resources(report):
    results = []
    for name, resource in report['resource_statuses'].iteritems():
        # Some of the fields should have a different key name from the report.
        result = {
            'name': name,
            'resource_title': resource['title'],
            'file_line': resource['line'],
        }
        # We want to set some values from the global report for correlation.
        for key in ['transaction_uuid', 'configuration_version', 'environment', 'host']:
            result[key] = report[key]
        # We only care about some of the fields on the resource.
        for key in ['resource_type', 'file', 'failed', 'changed', 'time', 'out_of_sync', 'skipped', 'change_count',
                    'out_of_sync_count']:
            result[key] = resource[key]
        results.append(result)
    return results


def prep_events(report):
    results = []
    for name, resource in report['resource_statuses'].iteritems():
        for event in resource['events']:
            result = dict()
            # We want to set some values from the global report for correlation.
            for key in ['transaction_uuid', 'configuration_version', 'environment', 'host']:
                result[key] = report[key]
            # These are actually all the fields in report version 4.
            for key in ['audited', 'property', 'previous_value', 'desired_value', 'historical_value', 'message', 'name',
                        'time', 'status']:
                result[key] = event[key]
            results.append(result)
    return results


def generate_actions(report, resources, events):
    actions = []
    report.update({'_index': 'puppet', '_type': 'report'})
    actions.append(report)
    for resource in resources:
        resource.update({'_index': 'puppet', '_type': 'resource_status'})
        actions.append(resource)
    for event in events:
        event.update({'_index': 'puppet', '_type': 'event'})
        actions.append(event)
    return actions


def es_submit(report, resources, events, config):
    actions = generate_actions(report=report, resources=resources, events=events)
    es = Elasticsearch([{'host': config['elasticsearch']['host'], 'port': config['elasticsearch']['port']}])
    oks, fails = elasticsearch.helpers.bulk(client=es, actions=actions, raise_on_error=False, raise_on_exception=False)
    logger.info('Submitted {0} documents to {1} from report on {2} with transaction_uuid {3}'.format(
        oks, config['elasticsearch']['host'], report['host'], report['transaction_uuid']))
    for err in fails:
        logger.exception(
            """
            Failed to submit data to {0}:
                Received status code {1}
                Error: {2}
                Exception: {3}
                Data: {4}
            """.format(config['elasticsearch']['host'], err['status'], err['error'], err['exception'], err['data']))
    if fails:
        msg = '{0} document(s) failed to index on {1}'.format(len(fails), config['elasticsearch']['host'])
        logger.exception(msg)
        raise elasticsearch.helpers.BulkIndexError(msg, fails)


def send_report(report, conf):
    if report['report_format'] != 4:
        msg = 'Cannot handle report version {}'.format(report['report_format'])
        logger.exception(msg)
        raise InvalidReport(msg)
    report_submit = prep_report(report)
    resources_submit = prep_resources(report)
    events_submit = prep_events(report)
    es_submit(report=report_submit, resources=resources_submit, events=events_submit, config=conf)


def main():
    global logger
    global syslog_handler
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    logger.addHandler(syslog_handler)
    if len(sys.argv) < 2 or sys.argv[1] == '-h' or sys.argv[1] == '--help':
        help()
        exit(0)
    try:
        conf = get_conf()
        prep_logging(conf.get('logging', dict()))
        report = parse_json(sys.argv[1])
        send_report(report, conf)
    except Exception as e:
        logger.exception(str(e))
        raise

