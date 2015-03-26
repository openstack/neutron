# Copyright 2011 VMware, Inc.
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
Routines for configuring Neutron
"""

import os
import sys

from keystoneclient import auth
from keystoneclient import session as ks_session
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging
import oslo_messaging
from paste import deploy

from neutron.api.v2 import attributes
from neutron.common import utils
from neutron.i18n import _LI
from neutron import version


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
    cfg.StrOpt('auth_strategy', default='keystone',
               help=_("The type of authentication to use")),
    cfg.StrOpt('core_plugin',
               help=_("The core plugin Neutron will use")),
    cfg.ListOpt('service_plugins', default=[],
                help=_("The service plugins Neutron will use")),
    cfg.StrOpt('base_mac', default="fa:16:3e:00:00:00",
               help=_("The base MAC address Neutron will use for VIFs")),
    cfg.IntOpt('mac_generation_retries', default=16,
               help=_("How many times Neutron will retry MAC generation")),
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
    cfg.StrOpt('default_ipv4_subnet_pool', default=None,
               help=_("Default IPv4 subnet-pool to be used for automatic "
                      "subnet CIDR allocation")),
    cfg.StrOpt('default_ipv6_subnet_pool', default=None,
               help=_("Default IPv6 subnet-pool to be used for automatic "
                      "subnet CIDR allocation")),
    cfg.IntOpt('dhcp_lease_duration', default=86400,
               deprecated_name='dhcp_lease_time',
               help=_("DHCP lease duration (in seconds). Use -1 to tell "
                      "dnsmasq to use infinite lease times.")),
    cfg.BoolOpt('dhcp_agent_notification', default=True,
                help=_("Allow sending resource operation"
                       " notification to DHCP agent")),
    cfg.BoolOpt('allow_overlapping_ips', default=False,
                help=_("Allow overlapping IP support in Neutron")),
    cfg.StrOpt('host', default=utils.get_hostname(),
               help=_("Hostname to be used by the neutron server, agents and "
                      "services running on this machine. All the agents and "
                      "services running on this machine must use the same "
                      "host value.")),
    cfg.BoolOpt('force_gateway_on_subnet', default=True,
                help=_("Ensure that configured gateway is on subnet. "
                       "For IPv6, validate only if gateway is not a link "
                       "local address. Deprecated, to be removed during the "
                       "K release, at which point the check will be "
                       "mandatory.")),
    cfg.BoolOpt('notify_nova_on_port_status_changes', default=True,
                help=_("Send notification to nova when port status changes")),
    cfg.BoolOpt('notify_nova_on_port_data_changes', default=True,
                help=_("Send notification to nova when port data (fixed_ips/"
                       "floatingip) changes so nova can update its cache.")),
    cfg.StrOpt('nova_url',
               default='http://127.0.0.1:8774/v2',
               help=_('URL for connection to nova. '
                      'Deprecated in favour of an auth plugin in [nova].')),
    cfg.StrOpt('nova_admin_username',
               help=_('Username for connecting to nova in admin context. '
                      'Deprecated in favour of an auth plugin in [nova].')),
    cfg.StrOpt('nova_admin_password',
               help=_('Password for connection to nova in admin context. '
                      'Deprecated in favour of an auth plugin in [nova].'),
               secret=True),
    cfg.StrOpt('nova_admin_tenant_id',
               help=_('The uuid of the admin nova tenant. '
                      'Deprecated in favour of an auth plugin in [nova].')),
    cfg.StrOpt('nova_admin_tenant_name',
               help=_('The name of the admin nova tenant. '
                      'Deprecated in favour of an auth plugin in [nova].')),
    cfg.StrOpt('nova_admin_auth_url',
               default='http://localhost:5000/v2.0',
               help=_('Authorization URL for connecting to nova in admin '
                      'context. '
                      'Deprecated in favour of an auth plugin in [nova].')),
    cfg.IntOpt('send_events_interval', default=2,
               help=_('Number of seconds between sending events to nova if '
                      'there are any events to send.')),
    cfg.BoolOpt('advertise_mtu', default=False,
                help=_('If True, effort is made to advertise MTU settings '
                       'to VMs via network methods (DHCP and RA MTU options) '
                       'when the network\'s preferred MTU is known.')),
    cfg.BoolOpt('vlan_transparent', default=False,
                help=_('If True, then allow plugins that support it to '
                       'create VLAN transparent networks.')),
]

core_cli_opts = [
    cfg.StrOpt('state_path',
               default='/var/lib/neutron',
               help=_("Where to store Neutron state files. "
                      "This directory must be writable by the agent.")),
]

# Register the configuration options
cfg.CONF.register_opts(core_opts)
cfg.CONF.register_cli_opts(core_cli_opts)

# Ensure that the control exchange is set correctly
oslo_messaging.set_transport_defaults(control_exchange='neutron')
_SQL_CONNECTION_DEFAULT = 'sqlite://'
# Update the default QueuePool parameters. These can be tweaked by the
# configuration variables - max_pool_size, max_overflow and pool_timeout
db_options.set_defaults(cfg.CONF,
                        connection=_SQL_CONNECTION_DEFAULT,
                        sqlite_db='', max_pool_size=10,
                        max_overflow=20, pool_timeout=10)

NOVA_CONF_SECTION = 'nova'

nova_deprecated_opts = {
    'cafile': [cfg.DeprecatedOpt('nova_ca_certificates_file', 'DEFAULT')],
    'insecure': [cfg.DeprecatedOpt('nova_api_insecure', 'DEFAULT')],
}
ks_session.Session.register_conf_options(cfg.CONF, NOVA_CONF_SECTION,
                                         deprecated_opts=nova_deprecated_opts)
auth.register_conf_options(cfg.CONF, NOVA_CONF_SECTION)

nova_opts = [
    cfg.StrOpt('region_name',
               deprecated_name='nova_region_name',
               deprecated_group='DEFAULT',
               help=_('Name of nova region to use. Useful if keystone manages'
                      ' more than one region.')),
]
cfg.CONF.register_opts(nova_opts, group=NOVA_CONF_SECTION)

logging.register_options(cfg.CONF)


def init(args, **kwargs):
    cfg.CONF(args=args, project='neutron',
             version='%%(prog)s %s' % version.version_info.release_string(),
             **kwargs)

    # FIXME(ihrachys): if import is put in global, circular import
    # failure occurs
    from neutron.common import rpc as n_rpc
    n_rpc.init(cfg.CONF)

    # Validate that the base_mac is of the correct format
    msg = attributes._validate_regex(cfg.CONF.base_mac,
                                     attributes.MAC_PATTERN)
    if msg:
        msg = _("Base MAC: %s") % msg
        raise Exception(msg)


def setup_logging():
    """Sets up the logging options for a log with supplied name."""
    product_name = "neutron"
    logging.setup(cfg.CONF, product_name)
    LOG.info(_LI("Logging enabled!"))
    LOG.info(_LI("%(prog)s version %(version)s"),
             {'prog': sys.argv[0],
              'version': version.version_info.release_string()})
    LOG.debug("command line: %s", " ".join(sys.argv))


def load_paste_app(app_name):
    """Builds and returns a WSGI app from a paste config file.

    :param app_name: Name of the application to load
    :raises ConfigFilesNotFoundError when config file cannot be located
    :raises RuntimeError when application cannot be loaded from config file
    """

    config_path = cfg.CONF.find_file(cfg.CONF.api_paste_config)
    if not config_path:
        raise cfg.ConfigFilesNotFoundError(
            config_files=[cfg.CONF.api_paste_config])
    config_path = os.path.abspath(config_path)
    LOG.info(_LI("Config paste file: %s"), config_path)

    try:
        app = deploy.loadapp("config:%s" % config_path, name=app_name)
    except (LookupError, ImportError):
        msg = (_("Unable to load %(app_name)s from "
                 "configuration file %(config_path)s.") %
               {'app_name': app_name,
                'config_path': config_path})
        LOG.exception(msg)
        raise RuntimeError(msg)
    return app
