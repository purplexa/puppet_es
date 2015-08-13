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


class ReportParseError(Exception):
    pass


class ExternalDependencyError(Exception):
    pass


class NonIdempotentElasticSearchError(Exception):
    pass


class InvalidReport(ValueError):
    pass


def prep_logging(conf):
    try:
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
    except Exception as e:
        msg = 'Something went wrong while configuring the logger: {}'.format(e)
        logger.exception(msg)
        raise ExternalDependencyError(msg)


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
        raise ExternalDependencyError(msg)
    except ValueError as e:
        msg = 'Could not parse JSON in {0}: {1}'.format(filename, e)
        logger.exception(msg)
        raise ExternalDependencyError(msg)
    except Exception as e:
        msg = 'Something went wrong while parsing the JSON report: {}'.format(e)
        logger.exception(msg)
        raise ExternalDependencyError(msg)


def get_conf():
    try:
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
        try:
            result['base']['on_error'] = conf.get('base', 'on_error')
            if result['base']['on_error'] == 'archive':
                try:
                    result['base']['archive_dir'] = conf.get('base', 'archive_dir')
                except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                    msg = 'Option "archive_dir" in section "base" is required if "on_error" is set to "archive"'
                    logger.exception(msg)
                    raise ValueError(msg)
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            # This is not a required parameter.
            pass
        try:
            result['base']['on_success'] = conf.get('base', 'on_success')
            if result['base']['on_success'] == 'archive':
                try:
                    result['base']['archive_dir'] = conf.get('base', 'archive_dir')
                except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                    msg = 'Option "archive_dir" in section "base" is required if "on_success" is set to "archive"'
                    logger.exception(msg)
                    raise ValueError(msg)
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            # This is not a required parameter.
            pass
        return result
    except Exception as e:
        msg = 'Something went wrong while loading the config file: {}'.format(e)
        logger.exception(msg)
        raise ExternalDependencyError(msg)


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
    try:
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
    except Exception as e:
        msg = 'Something went wrong while preparing the report object for submission: {}'.format(e)
        logger.exception(msg)
        raise ReportParseError(msg)


def prep_resources(report):
    try:
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
    except Exception as e:
        msg = 'Something went wrong while preparing the resource_status objects for submission: {}'.format(e)
        logger.exception(msg)
        raise ReportParseError(msg)


def prep_events(report):
    try:
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
    except Exception as e:
        msg = 'Something went wrong while preparing the event objects for submission: {}'.format(e)
        logger.exception(msg)
        raise ReportParseError(msg)


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
    try:
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
            msg1 = '{0} document(s) failed to index on {1}'.format(len(fails), config['elasticsearch']['host'])
            es_error = elasticsearch.helpers.BulkIndexError(msg1, fails)
            msg2 = 'Errors occurred while indexing: {}'.format(es_error)
            logger.exception(msg1)
            logger.exception(msg2)
            raise NonIdempotentElasticSearchError(msg2)
    except elasticsearch.ElasticsearchException as e:
        msg = 'Something went wrong while connecting to ElasticSearch: {}'.format(e)
        logger.exception(msg)
        raise ExternalDependencyError(msg)


def send_report(report, conf):
    if report['report_format'] != 4:
        msg = 'Cannot handle report version {}'.format(report['report_format'])
        logger.exception(msg)
        raise InvalidReport(msg)
    report_submit = prep_report(report)
    resources_submit = prep_resources(report)
    events_submit = prep_events(report)
    es_submit(report=report_submit, resources=resources_submit, events=events_submit, config=conf)


def handle_report_file(action, filename, archive_dir=None):
    if action == 'delete':
        logger.info('Deleting file {}'.format(filename))
        os.remove(filename)
    elif action == 'archive':
        if not archive_dir:
            raise ValueError('Cannot archive without archive_dir set')
        logger.info('Moving file {0} to {1}'.format(filename, archive_dir))
        os.rename(filename, '{0}/{1}'.format(archive_dir, os.path.basename(filename)))
    else:
        pass


def main():
    global logger
    global syslog_handler
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
    logger.addHandler(syslog_handler)
    if len(sys.argv) < 2 or sys.argv[1] == '-h' or sys.argv[1] == '--help':
        help()
        exit(0)
    try:
        filename = sys.argv[1]
        conf = get_conf()
        prep_logging(conf.get('logging', dict()))
        report = parse_json(filename)
        send_report(report, conf)
    except ReportParseError as e:
        logging.exception('Caught ReportParseError: {}'.format(e))
        if conf and 'base' in conf:
            behavior = conf['base'].get('on_error', 'ignore')
            handle_report_file(behavior, filename, conf['base'].get('archive_dir', None))
        else:
            handle_report_file('ignore', filename)
        raise
    except ExternalDependencyError as e:
        logging.exception('Caught ExternalDependencyError: {}'.format(e))
        raise
    except NonIdempotentElasticSearchError as e:
        logging.exception('Caught NonIdempotentElasticSearchError: {}'.format(e))
        if conf and 'base' in conf:
            behavior = conf['base'].get('on_error', 'ignore')
            handle_report_file(behavior, filename, conf['base'].get('archive_dir', None))
        else:
            handle_report_file('ignore', filename)
        raise
    except Exception as e:
        logging.exception('Caught Exception')
        logger.exception(str(e))
        raise
    else:
        logging.info('Successfully completed job')
        if conf and 'base' in conf:
            behavior = conf['base'].get('on_success', 'ignore')
            handle_report_file(behavior, filename, conf['base'].get('archive_dir', None))
        else:
            handle_report_file('ignore', filename)

