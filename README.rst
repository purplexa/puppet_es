send\_report\_to\_es
====================

Summary
-------

Send a puppet report to ElasticSearch.

Usage
-----

Command
~~~~~~~

::

    send_report_to_es [-h|--help] <filename>

Options
~~~~~~~

::

    -h/--help   Show this help text and exit

Parameters
~~~~~~~~~~

::

    filename    The JSON file for the report to load and send to ElasticSearch

Configuring
-----------

Configuration is read from the file specified in the environment
variable ``PUPPET_ES_CONFIG`` (defaults to ``/etc/puppet_es.conf``) and
uses ConfigParser syntax. A sample configuration file is included as
```etc/puppet_es.conf.example`` <etc/puppet_es.conf.example>`__.

Section: ``base``
~~~~~~~~~~~~~~~~~

**``on_error``** (optional) What to do with the report file when we
encounter a parse error or an ElasticSearch error. Possible values:

-  ``delete`` Delete the file off disk
-  ``archive`` Move the file to the directory specified in
   ``archive_dir``
-  ``ignore`` Leave the file as-is (default)

**``on_success``** (optional) What to do with the report file after
successfully posting to ElasticSearch. Possible values:

-  ``delete`` Delete the file off disk
-  ``archive`` Move the file to the directory specified in
   ``archive_dir``
-  ``ignore`` Leave the file as-is (default)

**``archive_dir``** (conditionally required) The directory to move files
into when ``archive`` is set for ``on_error`` or ``on_success``. Has no
effect if neither of those is set to ``archive``, and is required if
either is set to ``archive``.

Section: ``elasticsearch``
~~~~~~~~~~~~~~~~~~~~~~~~~~

**``host``** (required) The fully qualified domain name for connecting
to ElasticSearch over HTTP.

**``port``** (required) The port for connecting to ElasticSearch over
HTTP.

Section: ``logging``
~~~~~~~~~~~~~~~~~~~~

**``level``** (optional) What message level to log. Valid options are
those defined by the Python 2.7 ``logging`` module. Defaults to
``WARNING``.

**``stderr``** (optional) Boolean value about whether to print log
messages to ``stderr``. Defaults to ``false``.

**``syslog``** (optional) Boolean value about whether to print log
messages to syslog. Defaults to ``true``.

**``file``** (optional) Filename for a file to write log messages into.
Defaults to an empty value, meaning do not log to a file.

Configuring ElasticSearch
-------------------------

An example ElasticSearch template that supports the format this script
uses can be found at
```etc/puppet_template.json`` <etc/puppet_template.json>`__.
