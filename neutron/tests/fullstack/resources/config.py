# Copyright 2015 Red Hat, Inc.
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
import shutil
import tempfile

from neutron_lib import constants

from neutron.common import utils
from neutron.plugins.ml2.extensions import qos as qos_ext
from neutron.tests import base
from neutron.tests.common import config_fixtures
from neutron.tests.common.exclusive_resources import port
from neutron.tests.common import helpers as c_helpers
from neutron.tests.common import net_helpers
from neutron.tests.fullstack import base as fullstack_base

PHYSICAL_NETWORK_NAME = "physnet1"
MINIMUM_BANDWIDTH_INGRESS_KBPS = 1000
MINIMUM_BANDWIDTH_EGRESS_KBPS = 1000

NEUTRON_SERVER_PORT_START = 10000
NEUTRON_SERVER_PORT_END = 20000

OVS_OF_PORT_LISTEN_START = 20001
OVS_OF_PORT_LISTEN_END = 30000

CLIENT_CONN_PORT_START = 30001
CLIENT_CONN_PORT_END = 65000


class ConfigFixture(config_fixtures.ConfigFileFixture):
    """A fixture that holds an actual Neutron configuration.

    Note that 'self.config' is intended to only be updated once, during
    the constructor, so if this fixture is re-used (setUp is called twice),
    then the dynamic configuration values won't change. The correct usage
    is initializing a new instance of the class.
    """
    def __init__(self, env_desc, host_desc, temp_dir, base_filename):
        super(ConfigFixture, self).__init__(
            base_filename, config_fixtures.ConfigDict(), temp_dir)
        self.env_desc = env_desc
        self.host_desc = host_desc

    def _generate_namespace_suffix(self):
        return utils.get_rand_name(prefix='test')


class NeutronConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir,
                 connection, rabbitmq_environment, use_local_apipaste=True):
        super(NeutronConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='neutron.conf')

        self.config.update({
            'DEFAULT': {
                'host': self._generate_host(),
                'state_path': self._generate_state_path(self.temp_dir),
                'core_plugin': 'ml2',
                'service_plugins': env_desc.service_plugins,
                'auth_strategy': 'noauth',
                'debug': 'True',
                'global_physnet_mtu': str(env_desc.global_mtu),
                'agent_down_time': str(env_desc.agent_down_time),
                'transport_url':
                    'rabbit://%(user)s:%(password)s@%(host)s:5672/%(vhost)s' %
                    {'user': rabbitmq_environment.user,
                     'password': rabbitmq_environment.password,
                     'host': rabbitmq_environment.host,
                     'vhost': rabbitmq_environment.vhost},
                'api_workers': str(env_desc.api_workers),
            },
            'database': {
                'connection': connection,
            },
            'oslo_concurrency': {
                'lock_path': '$state_path/lock',
            },
            'agent': {
                'report_interval': str(env_desc.agent_down_time // 2),
                'log_agent_heartbeats': 'True',
            },
            'quotas': {
                'quota_driver': env_desc.quota_driver
            },
            'experimental': {
                'linuxbridge': str(env_desc.allow_experimental_linuxbridge)
            },
        })

        if use_local_apipaste:
            self.config['DEFAULT']['api_paste_config'] = (
                self._generate_api_paste())

        policy_file = self._generate_policy_yaml()
        if policy_file:
            self.config['oslo_policy'] = {'policy_file': policy_file}

        # Set root_helper/root_helper_daemon only when env var is set
        root_helper = os.environ.get('OS_ROOTWRAP_CMD')
        if root_helper:
            self.config['agent']['root_helper'] = root_helper
        root_helper_daemon = os.environ.get('OS_ROOTWRAP_DAEMON_CMD')
        if root_helper_daemon:
            self.config['agent']['root_helper_daemon'] = root_helper_daemon
        if env_desc.router_scheduler:
            self.config['DEFAULT']['router_scheduler_driver'] = (
                env_desc.router_scheduler)
        if env_desc.has_placement:
            service_plugins = self.config['DEFAULT']['service_plugins']
            self.config['DEFAULT']['service_plugins'] = (
                '%s,%s' % (service_plugins, 'placement')
            )
            self.config.update({
                'placement': {
                    'auth_type': 'noauth',
                    'auth_section': 'http://127.0.0.1:%s/placement' %
                    env_desc.placement_port
                }
            })
        if env_desc.dhcp_scheduler_class:
            self.config['DEFAULT']['dhcp_agents_per_network'] = '1'
            self.config['DEFAULT']['network_scheduler_driver'] = (
                env_desc.dhcp_scheduler_class)

        self.config['DEFAULT']['enable_traditional_dhcp'] = str(
            env_desc.enable_traditional_dhcp)

        net_helpers.set_local_port_range(CLIENT_CONN_PORT_START,
                                         CLIENT_CONN_PORT_END)

    def _setUp(self):
        self.config['DEFAULT'].update({
            'bind_port': self.useFixture(
                port.ExclusivePort(constants.PROTO_NAME_TCP,
                                   start=NEUTRON_SERVER_PORT_START,
                                   end=NEUTRON_SERVER_PORT_END)).port
        })
        super(NeutronConfigFixture, self)._setUp()

    def _generate_host(self):
        return utils.get_rand_name(prefix='host-')

    def _generate_state_path(self, temp_dir):
        # Assume that temp_dir will be removed by the caller
        self.state_path = tempfile.mkdtemp(prefix='state_path', dir=temp_dir)
        return self.state_path

    def _generate_api_paste(self):
        return c_helpers.find_sample_file('api-paste.ini')

    def _generate_policy_yaml(self):
        return c_helpers.find_sample_file('fullstack_tests_policy.yaml')

    def get_host(self):
        return self.config['DEFAULT']['host']


class ML2ConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, tenant_network_types):
        super(ML2ConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='ml2_conf.ini')

        mechanism_drivers = self.env_desc.mech_drivers
        if self.env_desc.l2_pop:
            mechanism_drivers += ',l2population'

        net_vlan_ranges_extra = ''
        if 'segments' in env_desc.service_plugins:
            net_vlan_ranges_extra = (',' + PHYSICAL_NETWORK_NAME +
                                     '_lb:1050:1059')

        self.config.update({
            'ml2': {
                'tenant_network_types': tenant_network_types,
                'mechanism_drivers': mechanism_drivers,
            },
            'ml2_type_vlan': {
                'network_vlan_ranges': PHYSICAL_NETWORK_NAME + ':1000:1029' +
                net_vlan_ranges_extra,
            },
            'ml2_type_gre': {
                'tunnel_id_ranges': '1:30',
            },
            'ml2_type_vxlan': {
                'vni_ranges': '1001:1030',
            },
        })

        extension_drivers = {'port_security'}
        if env_desc.qos:
            extension_drivers.add(qos_ext.QOS_EXT_DRIVER_ALIAS)
        if env_desc.ml2_extension_drivers:
            extension_drivers.update(env_desc.ml2_extension_drivers)
        self.config['ml2']['extension_drivers'] = ','.join(extension_drivers)


class OVSConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, local_ip, **kwargs):
        super(OVSConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='openvswitch_agent.ini')

        self.tunneling_enabled = self.env_desc.tunneling_enabled
        ext_dev = utils.get_rand_device_name(prefix='br-eth')
        self.config.update({
            'ovs': {
                'local_ip': local_ip,
                'integration_bridge': self._generate_integration_bridge(),
                'bridge_mappings': '%s:%s' % (PHYSICAL_NETWORK_NAME, ext_dev),
                'of_inactivity_probe': '0',
                'ovsdb_debug': 'True',
            },
            'securitygroup': {
                'firewall_driver': host_desc.firewall_driver,
            },
            'agent': {
                'l2_population': str(self.env_desc.l2_pop),
                'arp_responder': str(self.env_desc.arp_responder),
                'debug_iptables_rules': str(env_desc.debug_iptables),
                'use_helper_for_ns_read': 'False',
            }
        })

        if self.tunneling_enabled:
            self.config['agent'].update({
                'tunnel_types': self.env_desc.network_type})
            self.config['ovs'].update({
                'tunnel_bridge': self._generate_tunnel_bridge(),
                'int_peer_patch_port': self._generate_int_peer(),
                'tun_peer_patch_port': self._generate_tun_peer()})
        else:
            if env_desc.report_bandwidths:
                self.config['ovs'][constants.RP_BANDWIDTHS] = \
                    '%s:%s:%s' % (ext_dev, MINIMUM_BANDWIDTH_EGRESS_KBPS,
                                  MINIMUM_BANDWIDTH_INGRESS_KBPS)

        if env_desc.qos:
            self.config['agent']['extensions'] = 'qos'
        if env_desc.log:
            self.config['agent']['extensions'] = 'log'
            test_name = kwargs.get("test_name")
            test_name = base.sanitize_log_path(test_name)
            self.config.update({
                'network_log': {
                    'local_output_log_base':
                        self._generate_temp_log_file(test_name)}
            })
        if not env_desc.enable_traditional_dhcp:
            self.config['agent']['extensions'] = 'dhcp'
            self.config.update({
                'dhcp': {
                    'enable_ipv6': 'True',
                    'dhcp_renewal_time': '0',
                    'dhcp_rebinding_time': '0'}
            })
        if env_desc.local_ip_ext:
            self.config['agent']['extensions'] = 'local_ip'
            if host_desc.firewall_driver == 'openvswitch':
                self.config['local_ip'] = {'static_nat': 'True'}

    def _setUp(self):
        self.config['ovs'].update({
            'of_listen_port': self.useFixture(
                port.ExclusivePort(constants.PROTO_NAME_TCP,
                                   start=OVS_OF_PORT_LISTEN_START,
                                   end=OVS_OF_PORT_LISTEN_END)).port
        })
        super(OVSConfigFixture, self)._setUp()

    def _generate_integration_bridge(self):
        return utils.get_rand_device_name(prefix='br-int')

    def _generate_tunnel_bridge(self):
        return utils.get_rand_device_name(prefix='br-tun')

    def _generate_int_peer(self):
        return utils.get_rand_device_name(prefix='patch-tun')

    def _generate_tun_peer(self):
        return utils.get_rand_device_name(prefix='patch-int')

    def _generate_temp_log_file(self, test_name):
        log_dir_path = os.path.join(fullstack_base.DEFAULT_LOG_DIR, test_name)
        if not os.path.exists(log_dir_path):
            os.mkdir(log_dir_path, 0o755)
        return '%s/%s.log' % (log_dir_path,
                              utils.get_rand_name(prefix="test-sg-"))

    def get_br_int_name(self):
        return self.config.ovs.integration_bridge

    def get_br_phys_name(self):
        return self.config.ovs.bridge_mappings.split(':')[1]

    def get_br_tun_name(self):
        return self.config.ovs.tunnel_bridge


class SRIOVConfigFixture(ConfigFixture):
    def __init__(self, env_desc, host_desc, temp_dir, local_ip):
        super(SRIOVConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='sriov_agent.ini')

        device1 = utils.get_rand_device_name(prefix='ens5')
        device2 = utils.get_rand_device_name(prefix='ens6')
        phys_dev_mapping = '%s:%s,%s:%s' % (PHYSICAL_NETWORK_NAME, device1,
                                            PHYSICAL_NETWORK_NAME, device2)
        rp_bandwidths = '%s:%s:%s,%s:%s:%s' % (device1,
                                               MINIMUM_BANDWIDTH_EGRESS_KBPS,
                                               MINIMUM_BANDWIDTH_INGRESS_KBPS,
                                               device2,
                                               MINIMUM_BANDWIDTH_EGRESS_KBPS,
                                               MINIMUM_BANDWIDTH_INGRESS_KBPS)
        self.config.update({
            'sriov_nic': {
                'physical_device_mappings': phys_dev_mapping,
                'resource_provider_bandwidths': rp_bandwidths,
            }
        })

    def _setUp(self):
        super(SRIOVConfigFixture, self)._setUp()


class PlacementConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir):
        super(PlacementConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='placement.ini')
        self.config.update({
            'DEFAULT': {
                'debug': 'True',
                'placement_port': self.env_desc.placement_port
            }
        })

    def _setUp(self):
        super(PlacementConfigFixture, self)._setUp()


class LinuxBridgeConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, local_ip,
                 physical_device_name):
        super(LinuxBridgeConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename="linuxbridge_agent.ini"
        )
        self.service_plugins = env_desc.service_plugins

        self.config.update({
            'VXLAN': {
                'enable_vxlan': str(self.env_desc.tunneling_enabled),
                'local_ip': local_ip,
                'l2_population': str(self.env_desc.l2_pop),
            },
            'securitygroup': {
                'firewall_driver': host_desc.firewall_driver,
            },
            'AGENT': {
                'debug_iptables_rules': str(env_desc.debug_iptables),
                'use_helper_for_ns_read': 'False',
            }
        })
        if env_desc.qos:
            self.config.update({
                'AGENT': {
                    'extensions': 'qos'
                }
            })
        if self.env_desc.tunneling_enabled:
            self.config.update({
                'LINUX_BRIDGE': {
                    'bridge_mappings': self._generate_bridge_mappings(
                        physical_device_name
                    )
                }
            })
        else:
            self.config.update({
                'LINUX_BRIDGE': {
                    'physical_interface_mappings':
                        self._generate_bridge_mappings(
                            physical_device_name
                        )
                }
            })

    def _generate_bridge_mappings(self, device_name):
        bridge_mappings_extra = ('_lb' if 'segments' in self.service_plugins
                                 else '')
        return '%s%s:%s' % (PHYSICAL_NETWORK_NAME, bridge_mappings_extra,
                            device_name)


class L3ConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, integration_bridge=None):
        super(L3ConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='l3_agent.ini')
        if host_desc.l2_agent_type == constants.AGENT_TYPE_OVS:
            self._prepare_config_with_ovs_agent(integration_bridge)
        elif host_desc.l2_agent_type == constants.AGENT_TYPE_LINUXBRIDGE:
            self._prepare_config_with_linuxbridge_agent()
        if host_desc.l3_agent_mode:
            self.config['DEFAULT'].update({
                'agent_mode': host_desc.l3_agent_mode})
        self.config['DEFAULT'].update({
            'debug': 'True',
            'test_namespace_suffix': self._generate_namespace_suffix(),
            'ha_keepalived_state_change_server_threads': '1',
        })
        self.config.update({
            'agent': {'use_helper_for_ns_read': 'False'}
        })
        if host_desc.availability_zone:
            self.config['agent'].update({
                'availability_zone': host_desc.availability_zone
            })
        if host_desc.l3_agent_extensions:
            self.config['agent'].update({
                'extensions': host_desc.l3_agent_extensions
            })

    def _prepare_config_with_ovs_agent(self, integration_bridge):
        self.config.update({
            'DEFAULT': {
                'interface_driver': ('neutron.agent.linux.interface.'
                                     'OVSInterfaceDriver'),
            },
            'OVS': {
                'integration_bridge': integration_bridge,
            }
        })

    def _prepare_config_with_linuxbridge_agent(self):
        self.config.update({
            'DEFAULT': {
                'interface_driver': ('neutron.agent.linux.interface.'
                                     'BridgeInterfaceDriver'),
            }
        })


class DhcpConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, integration_bridge=None):
        super(DhcpConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='dhcp_agent.ini')

        if host_desc.l2_agent_type == constants.AGENT_TYPE_OVS:
            self._prepare_config_with_ovs_agent(integration_bridge)
        elif host_desc.l2_agent_type == constants.AGENT_TYPE_LINUXBRIDGE:
            self._prepare_config_with_linuxbridge_agent()
        self.config['DEFAULT'].update({
            'debug': 'True',
            'dhcp_confs': self._generate_dhcp_path(),
            'test_namespace_suffix': self._generate_namespace_suffix()
        })
        self.config.update({
            'AGENT': {'use_helper_for_ns_read': 'False'}
        })
        if host_desc.availability_zone:
            self.config['AGENT'].update({
                'availability_zone': host_desc.availability_zone
            })

    def _setUp(self):
        super(DhcpConfigFixture, self)._setUp()
        self.addCleanup(self._clean_dhcp_path)

    def _prepare_config_with_ovs_agent(self, integration_bridge):
        self.config.update({
            'DEFAULT': {
                'interface_driver': 'openvswitch',
            },
            'OVS': {
                'integration_bridge': integration_bridge,
            }
        })

    def _prepare_config_with_linuxbridge_agent(self):
        self.config.update({
            'DEFAULT': {
                'interface_driver': 'linuxbridge',
            }
        })

    def _generate_dhcp_path(self):
        # NOTE(slaweq): dhcp_conf path needs to be directory with read
        # permission for everyone, otherwise dnsmasq process will not be able
        # to read his configs
        self.dhcp_path = tempfile.mkdtemp(prefix="dhcp_configs_", dir="/tmp/")
        os.chmod(self.dhcp_path, 0o755)
        return self.dhcp_path

    def _clean_dhcp_path(self):
        shutil.rmtree(self.dhcp_path, ignore_errors=True)
