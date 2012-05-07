==============
quantum-server
==============

--------------
Quantum Server
--------------

:Author: openstack@lists.launchpad.net
:Date:   2012-04-05
:Copyright: OpenStack LLC
:Version: 2012.1
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

  quantum-server [options]

DESCRIPTION
===========

quantum-server provides a webserver that exposes the Quantum API, and
passes all webservice calls to the Quantum plugin for processing.

OPTIONS
=======

  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v, --verbose         Print more verbose output
  -d, --debug           Print debugging output
  --config-file=PATH    Path to the config file to use, for example,
                        /etc/quantum/quantum.conf. When not specified
                        (the default), we generally look at the first argument
                        specified to be a config file, and if that is also
                        missing, we search standard directories for a config
                        file. (/etc/quantum/,
                        /usr/lib/pythonX/site-packages/quantum/)

  Logging Options:
    The following configuration options are specific to logging
    functionality for this program.

    --log-config=PATH   If this option is specified, the logging configuration
                        file specified is used and overrides any other logging
                        options specified. Please see the Python logging
                        module documentation for details on logging
                        configuration files.
    --log-date-format=FORMAT
                        Format string for %(asctime)s in log records. Default:
                        %Y-%m-%d %H:%M:%S
    --use-syslog        Output logs to syslog.
    --log-file=PATH     (Optional) Name of log file to output to. If not set,
                        logging will go to stdout.
    --log-dir=LOG_DIR   (Optional) The directory to keep log files in (will be
                        prepended to --logfile)

FILES
========

plugins.ini file contains the plugin information
quantum.conf file contains configuration information in the form of python-gflags.

SEE ALSO
========

* `OpenStack Quantum <http://quantum.openstack.org>`__

BUGS
====

* Quantum is sourced in Launchpad so you can view current bugs at `OpenStack Bugs <https://bugs.launchpad.net/quantum>`__

