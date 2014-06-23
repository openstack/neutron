# Copyright 2012 OpenStack Foundation
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

import os

from oslo.config import cfg

from neutron.common import config
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)


ROOT_HELPER_OPTS = [
    cfg.StrOpt('root_helper', default='sudo',
               help=_('Root helper application.')),
]

AGENT_STATE_OPTS = [
    cfg.FloatOpt('report_interval', default=30,
                 help=_('Seconds between nodes reporting state to server; '
                        'should be less than agent_down_time, best if it '
                        'is half or less than agent_down_time.')),
]

INTERFACE_DRIVER_OPTS = [
    cfg.StrOpt('interface_driver',
               help=_("The driver used to manage the virtual interface.")),
]

USE_NAMESPACES_OPTS = [
    cfg.BoolOpt('use_namespaces', default=True,
                help=_("Allow overlapping IP.")),
]


def get_log_args(conf, log_file_name):
    cmd_args = []
    if conf.debug:
        cmd_args.append('--debug')
    if conf.verbose:
        cmd_args.append('--verbose')
    if (conf.log_dir or conf.log_file):
        cmd_args.append('--log-file=%s' % log_file_name)
        log_dir = None
        if conf.log_dir and conf.log_file:
            log_dir = os.path.dirname(
                os.path.join(conf.log_dir, conf.log_file))
        elif conf.log_dir:
            log_dir = conf.log_dir
        elif conf.log_file:
            log_dir = os.path.dirname(conf.log_file)
        if log_dir:
            cmd_args.append('--log-dir=%s' % log_dir)
    else:
        if conf.use_syslog:
            cmd_args.append('--use-syslog')
            if conf.syslog_log_facility:
                cmd_args.append(
                    '--syslog-log-facility=%s' % conf.syslog_log_facility)
    return cmd_args


def register_root_helper(conf):
    # The first call is to ensure backward compatibility
    conf.register_opts(ROOT_HELPER_OPTS)
    conf.register_opts(ROOT_HELPER_OPTS, 'AGENT')


def register_agent_state_opts_helper(conf):
    conf.register_opts(AGENT_STATE_OPTS, 'AGENT')


def register_interface_driver_opts_helper(conf):
    conf.register_opts(INTERFACE_DRIVER_OPTS)


def register_use_namespaces_opts_helper(conf):
    conf.register_opts(USE_NAMESPACES_OPTS)


def get_root_helper(conf):
    root_helper = conf.AGENT.root_helper
    if root_helper != 'sudo':
        return root_helper

    root_helper = conf.root_helper
    if root_helper != 'sudo':
        LOG.deprecated(_('DEFAULT.root_helper is deprecated! Please move '
                         'root_helper configuration to [AGENT] section.'))
        return root_helper

    return 'sudo'


def setup_conf():
    bind_opts = [
        cfg.StrOpt('state_path',
                   default='/var/lib/neutron',
                   help=_('Top-level directory for maintaining dhcp state')),
    ]

    conf = cfg.ConfigOpts()
    conf.register_opts(bind_opts)
    return conf

# add a logging setup method here for convenience
setup_logging = config.setup_logging
