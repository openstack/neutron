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
import shlex

from oslo_config import cfg
from oslo_privsep import priv_context

from neutron._i18n import _
from neutron.common import config


EXTERNAL_PROCESS_OPTS = [
    cfg.StrOpt('external_pids',
               default='$state_path/external/pids',
               help=_('Location to store child pid files')),
]


PD_OPTS = [
    cfg.StrOpt('pd_dhcp_driver',
               default='dibbler',
               help=_('Service to handle DHCPv6 Prefix delegation.')),
]


PD_DRIVER_OPTS = [
    cfg.StrOpt('pd_confs',
               default='$state_path/pd',
               help=_('Location to store IPv6 PD files.')),
    cfg.StrOpt('vendor_pen',
               default='8888',
               help=_("A decimal value as Vendor's Registered Private "
                      "Enterprise Number as required by RFC3315 DUID-EN.")),
]


INTERFACE_OPTS = [
    cfg.StrOpt('ovs_integration_bridge',
               default='br-int',
               deprecated_for_removal=True,
               deprecated_reason='This variable is a duplicate of '
                                 'OVS.integration_bridge. To be removed in W.',
               help=_('Name of Open vSwitch bridge to use')),
    cfg.BoolOpt('ovs_use_veth',
                default=False,
                help=_("Uses veth for an OVS interface or not. "
                       "Support kernels with limited namespace support "
                       "(e.g. RHEL 6.5) and rate limiting on router's gateway "
                       "port so long as ovs_use_veth is set to "
                       "True.")),
]


RA_OPTS = [
    cfg.StrOpt('ra_confs',
               default='$state_path/ra',
               help=_('Location to store IPv6 RA config files')),
    cfg.IntOpt('min_rtr_adv_interval',
               default=30,
               help=_('MinRtrAdvInterval setting for radvd.conf')),
    cfg.IntOpt('max_rtr_adv_interval',
               default=100,
               help=_('MaxRtrAdvInterval setting for radvd.conf')),
]


ROOT_HELPER_OPTS = [
    cfg.StrOpt('root_helper', default='sudo',
               help=_("Root helper application. "
                      "Use 'sudo neutron-rootwrap /etc/neutron/rootwrap.conf' "
                      "to use the real root filter facility. Change to 'sudo' "
                      "to skip the filtering and just run the command "
                      "directly.")),
    cfg.BoolOpt('use_helper_for_ns_read',
                default=True,
                help=_("Use the root helper when listing the namespaces on a "
                       "system. This may not be required depending on the "
                       "security configuration. If the root helper is "
                       "not required, set this to False for a performance "
                       "improvement.")),
    # We can't just use root_helper=sudo neutron-rootwrap-daemon $cfg because
    # it isn't appropriate for long-lived processes spawned with create_process
    # Having a bool use_rootwrap_daemon option precludes specifying the
    # rootwrap daemon command, which may be necessary for Xen?
    cfg.StrOpt('root_helper_daemon',
               help=_("""
Root helper daemon application to use when possible.

Use 'sudo neutron-rootwrap-daemon /etc/neutron/rootwrap.conf' to run rootwrap
in "daemon mode" which has been reported to improve performance at scale. For
more information on running rootwrap in "daemon mode", see:

https://docs.openstack.org/oslo.rootwrap/latest/user/usage.html#daemon-mode

For the agent which needs to execute commands in Dom0 in the hypervisor of
XenServer, this option should be set to 'xenapi_root_helper', so that it will
keep a XenAPI session to pass commands to Dom0.
""")),
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

IPTABLES_OPTS = [
    cfg.BoolOpt('comment_iptables_rules', default=True,
                help=_("Add comments to iptables rules. "
                       "Set to false to disallow the addition of comments to "
                       "generated iptables rules that describe each rule's "
                       "purpose. System must support the iptables comments "
                       "module for addition of comments.")),
    cfg.BoolOpt('debug_iptables_rules', default=False,
                help=_("Duplicate every iptables difference calculation to "
                       "ensure the format being generated matches the format "
                       "of iptables-save. This option should not be turned "
                       "on for production systems because it imposes a "
                       "performance penalty.")),
]

PROCESS_MONITOR_OPTS = [
    cfg.StrOpt('check_child_processes_action', default='respawn',
               choices=['respawn', 'exit'],
               help=_('Action to be executed when a child process dies')),
    cfg.IntOpt('check_child_processes_interval', default=60,
               help=_('Interval between checks of child process liveness '
                      '(seconds), use 0 to disable')),
    cfg.StrOpt('kill_scripts_path', default='/etc/neutron/kill_scripts/',
               help=_('Location of scripts used to kill external processes. '
                      'Names of scripts here must follow the pattern: '
                      '"<process-name>-kill" where <process-name> is name of '
                      'the process which should be killed using this script. '
                      'For example, kill script for dnsmasq process should be '
                      'named "dnsmasq-kill". '
                      'If path is set to None, then default "kill" command '
                      'will be used to stop processes.')),
]

AVAILABILITY_ZONE_OPTS = [
    # The default AZ name "nova" is selected to match the default
    # AZ name in Nova and Cinder.
    cfg.StrOpt('availability_zone', max_length=255, default='nova',
               help=_("Availability zone of this node")),
]


def get_log_args(conf, log_file_name, **kwargs):
    cmd_args = []
    if conf.debug:
        cmd_args.append('--debug')
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


def register_external_process_opts(cfg=cfg.CONF):
    cfg.register_opts(EXTERNAL_PROCESS_OPTS)


def register_pd_opts(cfg=cfg.CONF):
    cfg.register_opts(PD_OPTS)


def register_pddriver_opts(cfg=cfg.CONF):
    cfg.register_opts(PD_DRIVER_OPTS)


def register_interface_opts(cfg=cfg.CONF):
    cfg.register_opts(INTERFACE_OPTS)


def register_ra_opts(cfg=cfg.CONF):
    cfg.register_opts(RA_OPTS)


def register_root_helper(conf=cfg.CONF):
    conf.register_opts(ROOT_HELPER_OPTS, 'AGENT')


def register_agent_state_opts_helper(conf):
    conf.register_opts(AGENT_STATE_OPTS, 'AGENT')


def register_interface_driver_opts_helper(conf):
    conf.register_opts(INTERFACE_DRIVER_OPTS)


def register_iptables_opts(conf):
    conf.register_opts(IPTABLES_OPTS, 'AGENT')


def register_process_monitor_opts(conf):
    conf.register_opts(PROCESS_MONITOR_OPTS, 'AGENT')


def register_availability_zone_opts_helper(conf):
    conf.register_opts(AVAILABILITY_ZONE_OPTS, 'AGENT')


def get_root_helper(conf):
    return conf.AGENT.root_helper


def setup_conf():
    bind_opts = [
        cfg.StrOpt('state_path',
                   default='/var/lib/neutron',
                   help=_("Where to store Neutron state files. "
                          "This directory must be writable by the agent.")),
    ]

    conf = cfg.ConfigOpts()
    conf.register_opts(bind_opts)
    return conf


# add a logging setup method here for convenience
setup_logging = config.setup_logging


def setup_privsep():
    priv_context.init(root_helper=shlex.split(get_root_helper(cfg.CONF)))
