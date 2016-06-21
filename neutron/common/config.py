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

import sys

from keystoneauth1 import loading as ks_loading
from neutron_lib.api import validators
from oslo_config import cfg
from oslo_db import options as db_options
from oslo_log import log as logging
import oslo_messaging
from oslo_middleware import cors
from oslo_service import wsgi

from neutron._i18n import _, _LI
from neutron import api
from neutron.common import constants
from neutron.common import utils
from neutron import policy
from neutron import version


LOG = logging.getLogger(__name__)

core_opts = [
    cfg.StrOpt('bind_host', default='0.0.0.0',
               help=_("The host IP to bind to")),
    cfg.PortOpt('bind_port', default=9696,
                help=_("The port to bind to")),
    cfg.StrOpt('api_extensions_path', default="",
               help=_("The path for API extensions. "
                      "Note that this can be a colon-separated list of paths. "
                      "For example: api_extensions_path = "
                      "extensions:/path/to/more/exts:/even/more/exts. "
                      "The __path__ of neutron.extensions is appended to "
                      "this, so if your extensions are in there you don't "
                      "need to specify them here.")),
    cfg.StrOpt('auth_strategy', default='keystone',
               help=_("The type of authentication to use")),
    cfg.StrOpt('core_plugin',
               help=_("The core plugin Neutron will use")),
    cfg.ListOpt('service_plugins', default=[],
                help=_("The service plugins Neutron will use")),
    cfg.StrOpt('base_mac', default="fa:16:3e:00:00:00",
               help=_("The base MAC address Neutron will use for VIFs. "
                      "The first 3 octets will remain unchanged. If the 4th "
                      "octet is not 00, it will also be used. The others "
                      "will be randomly generated.")),
    cfg.IntOpt('mac_generation_retries', default=16,
               deprecated_for_removal=True,
               help=_("How many times Neutron will retry MAC generation. This "
                      "option is now obsolete and so is deprecated to be "
                      "removed in the Ocata release.")),
    cfg.BoolOpt('allow_bulk', default=True,
                help=_("Allow the usage of the bulk API")),
    cfg.BoolOpt('allow_pagination', default=api.DEFAULT_ALLOW_PAGINATION,
                help=_("Allow the usage of the pagination")),
    cfg.BoolOpt('allow_sorting', default=api.DEFAULT_ALLOW_SORTING,
                help=_("Allow the usage of the sorting")),
    cfg.StrOpt('pagination_max_limit', default="-1",
               help=_("The maximum number of items returned in a single "
                      "response, value was 'infinite' or negative integer "
                      "means no limit")),
    cfg.ListOpt('default_availability_zones', default=[],
                help=_("Default value of availability zone hints. The "
                       "availability zone aware schedulers use this when "
                       "the resources availability_zone_hints is empty. "
                       "Multiple availability zones can be specified by a "
                       "comma separated string. This value can be empty. "
                       "In this case, even if availability_zone_hints for "
                       "a resource is empty, availability zone is "
                       "considered for high availability while scheduling "
                       "the resource.")),
    cfg.IntOpt('max_dns_nameservers', default=5,
               help=_("Maximum number of DNS nameservers per subnet")),
    cfg.IntOpt('max_subnet_host_routes', default=20,
               help=_("Maximum number of host routes per subnet")),
    cfg.IntOpt('max_fixed_ips_per_port', default=5,
               deprecated_for_removal=True,
               help=_("Maximum number of fixed ips per port. This option "
                      "is deprecated and will be removed in the N "
                      "release.")),
    cfg.StrOpt('default_ipv4_subnet_pool', deprecated_for_removal=True,
               help=_("Default IPv4 subnet pool to be used for automatic "
                      "subnet CIDR allocation. "
                      "Specifies by UUID the pool to be used in case where "
                      "creation of a subnet is being called without a "
                      "subnet pool ID. If not set then no pool "
                      "will be used unless passed explicitly to the subnet "
                      "create. If no pool is used, then a CIDR must be passed "
                      "to create a subnet and that subnet will not be "
                      "allocated from any pool; it will be considered part of "
                      "the tenant's private address space. This option is "
                      "deprecated for removal in the N release.")),
    cfg.StrOpt('default_ipv6_subnet_pool', deprecated_for_removal=True,
               help=_("Default IPv6 subnet pool to be used for automatic "
                      "subnet CIDR allocation. "
                      "Specifies by UUID the pool to be used in case where "
                      "creation of a subnet is being called without a "
                      "subnet pool ID. See the description for "
                      "default_ipv4_subnet_pool for more information. This "
                      "option is deprecated for removal in the N release.")),
    cfg.BoolOpt('ipv6_pd_enabled', default=False,
                help=_("Enables IPv6 Prefix Delegation for automatic subnet "
                       "CIDR allocation. "
                       "Set to True to enable IPv6 Prefix Delegation for "
                       "subnet allocation in a PD-capable environment. Users "
                       "making subnet creation requests for IPv6 subnets "
                       "without providing a CIDR or subnetpool ID will be "
                       "given a CIDR via the Prefix Delegation mechanism. "
                       "Note that enabling PD will override the behavior of "
                       "the default IPv6 subnetpool.")),
    cfg.IntOpt('dhcp_lease_duration', default=86400,
               deprecated_name='dhcp_lease_time',
               help=_("DHCP lease duration (in seconds). Use -1 to tell "
                      "dnsmasq to use infinite lease times.")),
    cfg.StrOpt('dns_domain',
               default='openstacklocal',
               help=_('Domain to use for building the hostnames')),
    cfg.StrOpt('external_dns_driver',
               help=_('Driver for external DNS integration.')),
    cfg.BoolOpt('dhcp_agent_notification', default=True,
                help=_("Allow sending resource operation"
                       " notification to DHCP agent")),
    cfg.BoolOpt('allow_overlapping_ips', default=False,
                help=_("Allow overlapping IP support in Neutron. "
                       "Attention: the following parameter MUST be set to "
                       "False if Neutron is being used in conjunction with "
                       "Nova security groups.")),
    cfg.StrOpt('host', default=utils.get_hostname(),
               sample_default='example.domain',
               help=_("Hostname to be used by the Neutron server, agents and "
                      "services running on this machine. All the agents and "
                      "services running on this machine must use the same "
                      "host value.")),
    cfg.BoolOpt('notify_nova_on_port_status_changes', default=True,
                help=_("Send notification to nova when port status changes")),
    cfg.BoolOpt('notify_nova_on_port_data_changes', default=True,
                help=_("Send notification to nova when port data (fixed_ips/"
                       "floatingip) changes so nova can update its cache.")),
    cfg.IntOpt('send_events_interval', default=2,
               help=_('Number of seconds between sending events to nova if '
                      'there are any events to send.')),
    cfg.BoolOpt('advertise_mtu', default=True,
                deprecated_for_removal=True,
                help=_('If True, advertise network MTU values if core plugin '
                       'calculates them. MTU is advertised to running '
                       'instances via DHCP and RA MTU options.')),
    cfg.StrOpt('ipam_driver',
               help=_("Neutron IPAM (IP address management) driver to use. "
                      "If ipam_driver is not set (default behavior), no IPAM "
                      "driver is used. In order to use the reference "
                      "implementation of Neutron IPAM driver, "
                      "use 'internal'.")),
    cfg.BoolOpt('vlan_transparent', default=False,
                help=_('If True, then allow plugins that support it to '
                       'create VLAN transparent networks.')),
    cfg.StrOpt('web_framework', default='legacy',
               choices=('legacy', 'pecan'),
               help=_("This will choose the web framework in which to run "
                      "the Neutron API server. 'pecan' is a new experiemental "
                      "rewrite of the API server.")),
    cfg.IntOpt('global_physnet_mtu', default=constants.DEFAULT_NETWORK_MTU,
               deprecated_name='segment_mtu', deprecated_group='ml2',
               help=_('MTU of the underlying physical network. Neutron uses '
                      'this value to calculate MTU for all virtual network '
                      'components. For flat and VLAN networks, neutron uses '
                      'this value without modification. For overlay networks '
                      'such as VXLAN, neutron automatically subtracts the '
                      'overlay protocol overhead from this value. Defaults '
                      'to 1500, the standard value for Ethernet.'))
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
wsgi.register_opts(cfg.CONF)

# Ensure that the control exchange is set correctly
oslo_messaging.set_transport_defaults(control_exchange='neutron')


def set_db_defaults():
    # Update the default QueuePool parameters. These can be tweaked by the
    # conf variables - max_pool_size, max_overflow and pool_timeout
    db_options.set_defaults(
        cfg.CONF,
        connection='sqlite://',
        sqlite_db='', max_pool_size=10,
        max_overflow=20, pool_timeout=10)

set_db_defaults()

NOVA_CONF_SECTION = 'nova'

ks_loading.register_auth_conf_options(cfg.CONF, NOVA_CONF_SECTION)
ks_loading.register_session_conf_options(cfg.CONF, NOVA_CONF_SECTION)

nova_opts = [
    cfg.StrOpt('region_name',
               help=_('Name of nova region to use. Useful if keystone manages'
                      ' more than one region.')),
    cfg.StrOpt('endpoint_type',
               default='public',
               choices=['public', 'admin', 'internal'],
               help=_('Type of the nova endpoint to use.  This endpoint will'
                      ' be looked up in the keystone catalog and should be'
                      ' one of public, internal or admin.')),
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
    msg = validators.validate_regex(cfg.CONF.base_mac, validators.MAC_PATTERN)
    if msg:
        msg = _("Base MAC: %s") % msg
        raise Exception(msg)


def setup_logging():
    """Sets up the logging options for a log with supplied name."""
    product_name = "neutron"
    logging.setup(cfg.CONF, product_name)
    # We use the oslo.log default log levels and add only the extra levels
    # that Neutron needs.
    logging.set_defaults(default_log_levels=logging.get_default_log_levels())
    LOG.info(_LI("Logging enabled!"))
    LOG.info(_LI("%(prog)s version %(version)s"),
             {'prog': sys.argv[0],
              'version': version.version_info.release_string()})
    LOG.debug("command line: %s", " ".join(sys.argv))


def reset_service():
    # Reset worker in case SIGHUP is called.
    # Note that this is called only in case a service is running in
    # daemon mode.
    setup_logging()
    set_config_defaults()
    policy.refresh()


def load_paste_app(app_name):
    """Builds and returns a WSGI app from a paste config file.

    :param app_name: Name of the application to load
    """
    loader = wsgi.Loader(cfg.CONF)
    app = loader.load_app(app_name)
    return app


def set_config_defaults():
    """This method updates all configuration default values."""
    set_cors_middleware_defaults()


def set_cors_middleware_defaults():
    """Update default configuration options for oslo.middleware."""
    # CORS Defaults
    # TODO(krotscheck): Update with https://review.openstack.org/#/c/285368/
    cfg.set_defaults(cors.CORS_OPTS,
                     allow_headers=['X-Auth-Token',
                                    'X-Identity-Status',
                                    'X-Roles',
                                    'X-Service-Catalog',
                                    'X-User-Id',
                                    'X-Tenant-Id',
                                    'X-OpenStack-Request-ID'],
                     expose_headers=['X-Auth-Token',
                                     'X-Subject-Token',
                                     'X-Service-Token',
                                     'X-OpenStack-Request-ID',
                                     'OpenStack-Volume-microversion'],
                     allow_methods=['GET',
                                    'PUT',
                                    'POST',
                                    'DELETE',
                                    'PATCH']
                     )
