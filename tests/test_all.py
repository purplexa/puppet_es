import itertools
import logging
import ConfigParser

from mock import call, MagicMock, NonCallableMagicMock, patch
import pytest

import puppet_es


@pytest.mark.parametrize(
    'config',
    [
        { 'logger': { 'level': 'WARNING' } },
        { 'logger': { 'level': 'WARNING', 'syslog': False } },
        { 'logger': { 'level': 'INFO', 'stderr': True, 'syslog': True }},
        { 'logger': { 'level': 'DEBUG', 'file': '/tmp/example.log'}},
    ])
@patch('puppet_es.logger', new_callable=NonCallableMagicMock)
@patch('puppet_es.logging.StreamHandler', autospec=True)
@patch('puppet_es.logging.FileHandler', autospec=True)
def test_prep_logging(mockFileH, mockStreamH, mockLogger, config):
    puppet_es.prep_logging(config, puppet_es.default_log_format.format('no file'))
    mockLogger.setLevel.assert_called_with(getattr(logging, config.get('level', 'WARNING')))
    info_calls = []
    add_calls = []
    if config.get('file'):
        add_calls.append(call(mockFileH(config.get('file'))))
        info_calls.append(call('Logging to file {}'.format(config.get('file'))))
    if config.get('stderr', False):
        add_calls(call(mockStreamH()))
        info_calls.append(call('Logging to stderr'))
    if config.get('syslog', True):
        assert mockLogger.removeHandler.call_count == 0
        info_calls.append(call('Logging to syslog'))
    else:
        assert mockLogger.removehandler.call_count == 1
    assert mockLogger.addHandler.has_calls(add_calls)
    assert mockLogger.info.has_calls(info_calls)


@pytest.mark.parametrize(
    'config,config_file',
    itertools.product([
        {
            'elasticsearch': { 'host': 'elasticsearch.example.com', 'port': 9200, },
        },
        {
            'elasticsearch': { 'host': 'elasticsearch.example.com', 'port': 9200, },
            'logging': { 'level': 'WARNING', },
        },
        {
            'elasticsearch': { 'host': 'elasticsearch.example.com', 'port': 9200, },
            'logging': { 'level': 'WARNING', 'syslog': True, },
        },
        {
            'elasticsearch': { 'host': 'elasticsearch.example.com', 'port': 9200, },
            'logging': { 'level': 'WARNING', 'syslog': True, 'stderr': False, },
        },
        {
            'elasticsearch': { 'host': 'elasticsearch.example.com', 'port': 9200, },
            'logging': { 'level': 'WARNING', 'syslog': True, 'stderr': False, 'file': '/tmp/example.log'},
        },
        {
            'logging': { 'level': 'WARNING', },
        },
        {
            'elasticsearch': { 'port': 9200, },
            'logging': { 'level': 'WARNING', },
        },
        {
            'elasticsearch': { 'host': 'elasticsearch.example.com', },
            'logging': { 'level': 'WARNING', },
        },
    ], [None, '/usr/local/etc/puppet_es.conf'])
)
@patch('puppet_es.os.environ.get', autospec=True)
def test_get_conf(mockOsEnvGet, config, config_file):
    mockOsEnvGet.return_value = config_file or '/etc/puppet_es.conf'
    rcp = ConfigParser.RawConfigParser()
    for section in config:
        rcp.add_section(section)
        for option in config[section]:
            value = config[section][option]
            if value is True:
                value = 'true'
            if value is False:
                value = 'false'
            rcp.set(section, option, value)
    rcpWrap = MagicMock(wraps=rcp)
    rcpWrap.read.return_value = None

    with patch('puppet_es.ConfigParser.RawConfigParser', autospec=True) as mockRCP:
        mockRCP.return_value = rcpWrap

        if not config.get('elasticsearch'):
            with pytest.raises(puppet_es.ExternalDependencyError) as excinfo:
                puppet_es.get_conf()
            assert 'elasticsearch' in str(excinfo.value)
            return

        if not config['elasticsearch'].get('host'):
            with pytest.raises(puppet_es.ExternalDependencyError) as excinfo:
                puppet_es.get_conf()
            assert 'host' in str(excinfo.value)
            return

        if not config['elasticsearch'].get('port'):
            with pytest.raises(puppet_es.ExternalDependencyError) as excinfo:
                puppet_es.get_conf()
            assert 'port' in str(excinfo.value)
            return

        try:
            rcp.getboolean('logging', 'syslog')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            # This is not a required parameter.
            pass
        except ValueError as e:
            with pytest.raises(puppet_es.ExternalDependencyError) as excinfo:
                puppet_es.get_conf()
            assert 'Not a boolean' in str(excinfo.value)
            return

        try:
            rcp.getboolean('logging', 'stderr')
        except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
            # This is not a required parameter.
            pass
        except ValueError as e:
            with pytest.raises(ValueError) as excinfo:
                puppet_es.get_conf()
            assert 'Not a boolean' in excinfo.value
            return

        assert puppet_es.get_conf() == config
        mockOsEnvGet.assert_called_with('PUPPET_ES_CONFIG', '/etc/puppet_es.conf')
        rcpWrap.read.assert_called_with(config_file or '/etc/puppet_es.conf')

