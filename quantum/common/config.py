# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 Nicira Networks, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Routines for configuring Quantum
"""

import logging
import logging.config
import logging.handlers
import os
import sys

from paste import deploy

from quantum.api.v2 import attributes
from quantum.openstack.common import cfg
from quantum.version import version_string


LOG = logging.getLogger(__name__)

core_opts = [
    cfg.StrOpt('bind_host', default='0.0.0.0'),
    cfg.IntOpt('bind_port', default=9696),
    cfg.StrOpt('api_paste_config', default="api-paste.ini"),
    cfg.StrOpt('api_extensions_path', default=""),
    cfg.StrOpt('policy_file', default="policy.json"),
    cfg.StrOpt('auth_strategy', default='keystone'),
    cfg.StrOpt('core_plugin',
               default='quantum.plugins.sample.SamplePlugin.FakePlugin'),
    cfg.StrOpt('base_mac', default="fa:16:3e:00:00:00"),
    cfg.IntOpt('mac_generation_retries', default=16),
    cfg.BoolOpt('allow_bulk', default=True),
    cfg.IntOpt('max_dns_nameservers', default=5),
    cfg.IntOpt('max_subnet_host_routes', default=20),
    cfg.StrOpt('state_path', default='.'),
    cfg.IntOpt('dhcp_lease_duration', default=120),
    cfg.BoolOpt('allow_overlapping_ips', default=False),
    cfg.StrOpt('control_exchange',
               default='quantum',
               help='AMQP exchange to connect to if using RabbitMQ or Qpid')

]

# Register the configuration options
cfg.CONF.register_opts(core_opts)


def parse(args):
    cfg.CONF(args=args, project='quantum',
             version='%%prog %s' % version_string())

    # Validate that the base_mac is of the correct format
    msg = attributes._validate_regex(cfg.CONF.base_mac,
                                     attributes.MAC_PATTERN)
    if msg:
        msg = "Base MAC: %s" % msg
        raise Exception(msg)


def setup_logging(conf):
    """
    Sets up the logging options for a log with supplied name

    :param conf: a cfg.ConfOpts object
    """

    if conf.log_config:
        # Use a logging configuration file for all settings...
        if os.path.exists(conf.log_config):
            logging.config.fileConfig(conf.log_config)
            return
        else:
            raise RuntimeError("Unable to locate specified logging "
                               "config file: %s" % conf.log_config)

    root_logger = logging.root
    if conf.debug:
        root_logger.setLevel(logging.DEBUG)
    elif conf.verbose:
        root_logger.setLevel(logging.INFO)
    else:
        root_logger.setLevel(logging.WARNING)

    formatter = logging.Formatter(conf.log_format, conf.log_date_format)

    if conf.use_syslog:
        try:
            facility = getattr(logging.handlers.SysLogHandler,
                               conf.syslog_log_facility)
        except AttributeError:
            raise ValueError(_("Invalid syslog facility"))

        handler = logging.handlers.SysLogHandler(address='/dev/log',
                                                 facility=facility)
    elif conf.log_file:
        logfile = conf.log_file
        if conf.log_dir:
            logfile = os.path.join(conf.log_dir, logfile)
        handler = logging.handlers.WatchedFileHandler(logfile)
    else:
        handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
    LOG.info("Logging enabled!")


def load_paste_app(app_name):
    """
    Builds and returns a WSGI app from a paste config file.

    :param app_name: Name of the application to load
    :raises RuntimeError when config file cannot be located or application
            cannot be loaded from config file
    """

    config_path = os.path.abspath(cfg.CONF.find_file(
        cfg.CONF.api_paste_config))
    LOG.info("Config paste file: %s", config_path)

    try:
        app = deploy.loadapp("config:%s" % config_path, name=app_name)
    except (LookupError, ImportError):
        msg = ("Unable to load %(app_name)s from "
               "configuration file %(config_path)s.") % locals()
        LOG.exception(msg)
        raise RuntimeError(msg)
    return app
