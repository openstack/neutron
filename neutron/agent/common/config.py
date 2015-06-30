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

from oslo_config import cfg
from oslo_log import log as logging

from neutron.common import config


LOG = logging.getLogger(__name__)


ROOT_HELPER_OPTS = [
    cfg.StrOpt('root_helper', default='sudo',
               help=_('Root helper application.')),
    cfg.BoolOpt('use_helper_for_ns_read',
                default=True,
                help=_('Use the root helper to read the namespaces from '
                       'the operating system.')),
    # We can't just use root_helper=sudo neutron-rootwrap-daemon $cfg because
    # it isn't appropriate for long-lived processes spawned with create_process
    # Having a bool use_rootwrap_daemon option precludes specifying the
    # rootwrap daemon command, which may be necessary for Xen?
    cfg.StrOpt('root_helper_daemon',
               help=_('Root helper daemon application to use when possible.')),
]

AGENT_STATE_OPTS = [
    cfg.FloatOpt('report_interval', default=30,
                 help=_('Seconds between nodes reporting state to server; '
                        'should be less than agent_down_time, best if it '
                        'is half or less than agent_down_time.')),
    cfg.BoolOpt('log_agent_heartbeats', default=False,
                help=_('Log agent heartbeats')),
]

INTERFACE_DRIVER_OPTS = [
    cfg.StrOpt('interface_driver',
               help=_("The driver used to manage the virtual interface.")),
]

USE_NAMESPACES_OPTS = [
    cfg.BoolOpt('use_namespaces', default=True,
                help=_("Allow overlapping IP. This option is deprecated and "
                       "will be removed in a future release."),
                deprecated_for_removal=True),
]

IPTABLES_OPTS = [
    cfg.BoolOpt('comment_iptables_rules', default=True,
                help=_("Add comments to iptables rules.")),
]

PROCESS_MONITOR_OPTS = [
    cfg.StrOpt('check_child_processes_action', default='respawn',
               choices=['respawn', 'exit'],
               help=_('Action to be executed when a child process dies')),
    cfg.IntOpt('check_child_processes_interval', default=60,
               help=_('Interval between checks of child process liveness '
                      '(seconds), use 0 to disable')),
]


def get_log_args(conf, log_file_name, **kwargs):
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
        if kwargs.get('metadata_proxy_watch_log') is False:
            cmd_args.append('--metadata_proxy_watch_log=false')
    else:
        if conf.use_syslog:
            cmd_args.append('--use-syslog')
            if conf.syslog_log_facility:
                cmd_args.append(
                    '--syslog-log-facility=%s' % conf.syslog_log_facility)
    return cmd_args


def register_root_helper(conf):
    conf.register_opts(ROOT_HELPER_OPTS, 'AGENT')


def register_agent_state_opts_helper(conf):
    conf.register_opts(AGENT_STATE_OPTS, 'AGENT')


def register_interface_driver_opts_helper(conf):
    conf.register_opts(INTERFACE_DRIVER_OPTS)


def register_use_namespaces_opts_helper(conf):
    conf.register_opts(USE_NAMESPACES_OPTS)


def register_iptables_opts(conf):
    conf.register_opts(IPTABLES_OPTS, 'AGENT')


def register_process_monitor_opts(conf):
    conf.register_opts(PROCESS_MONITOR_OPTS, 'AGENT')


def get_root_helper(conf):
    return conf.AGENT.root_helper


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
