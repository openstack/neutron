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

import os

from oslo.config import cfg
from paste import deploy

from quantum.api.v2 import attributes
from quantum.common import utils
from quantum.openstack.common import log as logging
from quantum.openstack.common import rpc
from quantum.version import version_info as quantum_version


LOG = logging.getLogger(__name__)

core_opts = [
    cfg.StrOpt('bind_host', default='0.0.0.0',
               help=_("The host IP to bind to")),
    cfg.IntOpt('bind_port', default=9696,
               help=_("The port to bind to")),
    cfg.StrOpt('api_paste_config', default="api-paste.ini",
               help=_("The API paste config file to use")),
    cfg.StrOpt('api_extensions_path', default="",
               help=_("The path for API extensions")),
    cfg.StrOpt('policy_file', default="policy.json",
               help=_("The policy file to use")),
    cfg.StrOpt('auth_strategy', default='keystone',
               help=_("The type of authentication to use")),
    cfg.StrOpt('core_plugin',
               help=_("The core plugin Quantum will use")),
    cfg.ListOpt('service_plugins', default=[],
                help=_("The service plugins Quantum will use")),
    cfg.StrOpt('base_mac', default="fa:16:3e:00:00:00",
               help=_("The base MAC address Quantum will use for VIFs")),
    cfg.IntOpt('mac_generation_retries', default=16,
               help=_("How many times Quantum will retry MAC generation")),
    cfg.BoolOpt('allow_bulk', default=True,
                help=_("Allow the usage of the bulk API")),
    cfg.BoolOpt('allow_pagination', default=False,
                help=_("Allow the usage of the pagination")),
    cfg.BoolOpt('allow_sorting', default=False,
                help=_("Allow the usage of the sorting")),
    cfg.StrOpt('pagination_max_limit', default="-1",
               help=_("The maximum number of items returned in a single "
                      "response, value was 'infinite' or negative integer "
                      "means no limit")),
    cfg.IntOpt('max_dns_nameservers', default=5,
               help=_("Maximum number of DNS nameservers")),
    cfg.IntOpt('max_subnet_host_routes', default=20,
               help=_("Maximum number of host routes per subnet")),
    cfg.IntOpt('max_fixed_ips_per_port', default=5,
               help=_("Maximum number of fixed ips per port")),
    cfg.IntOpt('dhcp_lease_duration', default=120,
               help=_("DHCP lease duration")),
    cfg.BoolOpt('dhcp_agent_notification', default=True,
                help=_("Allow sending resource operation"
                       " notification to DHCP agent")),
    cfg.BoolOpt('allow_overlapping_ips', default=False,
                help=_("Allow overlapping IP support in Quantum")),
    cfg.StrOpt('host', default=utils.get_hostname(),
               help=_("The hostname Quantum is running on")),
    cfg.BoolOpt('force_gateway_on_subnet', default=False,
                help=_("Ensure that configured gateway is on subnet")),
]

core_cli_opts = [
    cfg.StrOpt('state_path', default='/var/lib/quantum'),
]

# Register the configuration options
cfg.CONF.register_opts(core_opts)
cfg.CONF.register_cli_opts(core_cli_opts)

# Ensure that the control exchange is set correctly
rpc.set_defaults(control_exchange='quantum')


def parse(args):
    cfg.CONF(args=args, project='quantum',
             version='%%prog %s' % quantum_version.release_string())

    # Validate that the base_mac is of the correct format
    msg = attributes._validate_regex(cfg.CONF.base_mac,
                                     attributes.MAC_PATTERN)
    if msg:
        msg = _("Base MAC: %s") % msg
        raise Exception(msg)


def setup_logging(conf):
    """
    Sets up the logging options for a log with supplied name

    :param conf: a cfg.ConfOpts object
    """
    product_name = "quantum"
    logging.setup(product_name)
    LOG.info(_("Logging enabled!"))


def load_paste_app(app_name):
    """
    Builds and returns a WSGI app from a paste config file.

    :param app_name: Name of the application to load
    :raises RuntimeError when config file cannot be located or application
            cannot be loaded from config file
    """

    config_path = os.path.abspath(cfg.CONF.find_file(
        cfg.CONF.api_paste_config))
    LOG.info(_("Config paste file: %s"), config_path)

    try:
        app = deploy.loadapp("config:%s" % config_path, name=app_name)
    except (LookupError, ImportError):
        msg = _("Unable to load %(app_name)s from "
                "configuration file %(config_path)s.") % locals()
        LOG.exception(msg)
        raise RuntimeError(msg)
    return app
