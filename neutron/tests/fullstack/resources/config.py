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

import tempfile

import fixtures
from neutron_lib import constants

from neutron.common import utils
from neutron.plugins.ml2.extensions import qos as qos_ext
from neutron.tests.common import config_fixtures
from neutron.tests.common.exclusive_resources import port
from neutron.tests.common import helpers as c_helpers


class ConfigFixture(fixtures.Fixture):
    """A fixture that holds an actual Neutron configuration.

    Note that 'self.config' is intended to only be updated once, during
    the constructor, so if this fixture is re-used (setUp is called twice),
    then the dynamic configuration values won't change. The correct usage
    is initializing a new instance of the class.
    """
    def __init__(self, env_desc, host_desc, temp_dir, base_filename):
        super(ConfigFixture, self).__init__()
        self.config = config_fixtures.ConfigDict()
        self.env_desc = env_desc
        self.host_desc = host_desc
        self.temp_dir = temp_dir
        self.base_filename = base_filename

    def _setUp(self):
        cfg_fixture = config_fixtures.ConfigFileFixture(
            self.base_filename, self.config, self.temp_dir)
        self.useFixture(cfg_fixture)
        self.filename = cfg_fixture.filename


class NeutronConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir,
                 connection, rabbitmq_environment):
        super(NeutronConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='neutron.conf')

        service_plugins = ['router', 'trunk']
        if env_desc.qos:
            service_plugins.append('qos')

        self.config.update({
            'DEFAULT': {
                'host': self._generate_host(),
                'state_path': self._generate_state_path(self.temp_dir),
                'api_paste_config': self._generate_api_paste(),
                'core_plugin': 'ml2',
                'service_plugins': ','.join(service_plugins),
                'auth_strategy': 'noauth',
                'debug': 'True',
                'transport_url':
                    'rabbit://%(user)s:%(password)s@%(host)s:5672/%(vhost)s' %
                    {'user': rabbitmq_environment.user,
                     'password': rabbitmq_environment.password,
                     'host': rabbitmq_environment.host,
                     'vhost': rabbitmq_environment.vhost},
            },
            'database': {
                'connection': connection,
            },
            'oslo_concurrency': {
                'lock_path': '$state_path/lock',
            },
            'oslo_policy': {
                'policy_file': self._generate_policy_json(),
            },
        })

    def _setUp(self):
        self.config['DEFAULT'].update({
            'bind_port': self.useFixture(
                port.ExclusivePort(constants.PROTO_NAME_TCP)).port
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

    def _generate_policy_json(self):
        return c_helpers.find_sample_file('policy.json')


class ML2ConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, tenant_network_types):
        super(ML2ConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='ml2_conf.ini')

        mechanism_drivers = self.env_desc.mech_drivers
        if self.env_desc.l2_pop:
            mechanism_drivers += ',l2population'

        self.config.update({
            'ml2': {
                'tenant_network_types': tenant_network_types,
                'mechanism_drivers': mechanism_drivers,
            },
            'ml2_type_vlan': {
                'network_vlan_ranges': 'physnet1:1000:2999',
            },
            'ml2_type_gre': {
                'tunnel_id_ranges': '1:1000',
            },
            'ml2_type_vxlan': {
                'vni_ranges': '1001:2000',
            },
        })

        if env_desc.qos:
            self.config['ml2']['extension_drivers'] =\
                    qos_ext.QOS_EXT_DRIVER_ALIAS


class OVSConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, local_ip):
        super(OVSConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename='openvswitch_agent.ini')

        self.tunneling_enabled = self.env_desc.tunneling_enabled
        self.config.update({
            'ovs': {
                'local_ip': local_ip,
                'integration_bridge': self._generate_integration_bridge(),
                'of_interface': host_desc.of_interface,
                'ovsdb_interface': host_desc.ovsdb_interface,
            },
            'securitygroup': {
                'firewall_driver': 'noop',
            },
            'agent': {
                'l2_population': str(self.env_desc.l2_pop),
                'arp_responder': str(self.env_desc.arp_responder),
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
            self.config['ovs']['bridge_mappings'] = (
                self._generate_bridge_mappings())

        if env_desc.qos:
            self.config['agent']['extensions'] = 'qos'

    def _setUp(self):
        if self.config['ovs']['of_interface'] == 'native':
            self.config['ovs'].update({
                'of_listen_port': self.useFixture(
                    port.ExclusivePort(constants.PROTO_NAME_TCP)).port
            })
        super(OVSConfigFixture, self)._setUp()

    def _generate_bridge_mappings(self):
        return 'physnet1:%s' % utils.get_rand_device_name(prefix='br-eth')

    def _generate_integration_bridge(self):
        return utils.get_rand_device_name(prefix='br-int')

    def _generate_tunnel_bridge(self):
        return utils.get_rand_device_name(prefix='br-tun')

    def _generate_int_peer(self):
        return utils.get_rand_device_name(prefix='patch-tun')

    def _generate_tun_peer(self):
        return utils.get_rand_device_name(prefix='patch-int')

    def get_br_int_name(self):
        return self.config.ovs.integration_bridge

    def get_br_phys_name(self):
        return self.config.ovs.bridge_mappings.split(':')[1]

    def get_br_tun_name(self):
        return self.config.ovs.tunnel_bridge


class LinuxBridgeConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, local_ip,
                 physical_device_name):
        super(LinuxBridgeConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir,
            base_filename="linuxbridge_agent.ini"
        )
        self.config.update({
            'VXLAN': {
                'enable_vxlan': str(self.env_desc.tunneling_enabled),
                'local_ip': local_ip,
                'l2_population': str(self.env_desc.l2_pop),
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
        return 'physnet1:%s' % device_name


class L3ConfigFixture(ConfigFixture):

    def __init__(self, env_desc, host_desc, temp_dir, integration_bridge=None):
        super(L3ConfigFixture, self).__init__(
            env_desc, host_desc, temp_dir, base_filename='l3_agent.ini')
        if host_desc.l2_agent_type == constants.AGENT_TYPE_OVS:
            self._prepare_config_with_ovs_agent(integration_bridge)
        elif host_desc.l2_agent_type == constants.AGENT_TYPE_LINUXBRIDGE:
            self._prepare_config_with_linuxbridge_agent()
        self.config['DEFAULT'].update({
            'debug': 'True',
            'test_namespace_suffix': self._generate_namespace_suffix(),
        })

    def _prepare_config_with_ovs_agent(self, integration_bridge):
        self.config.update({
            'DEFAULT': {
                'interface_driver': ('neutron.agent.linux.interface.'
                                     'OVSInterfaceDriver'),
                'ovs_integration_bridge': integration_bridge,
                'external_network_bridge': self._generate_external_bridge(),
            }
        })

    def _prepare_config_with_linuxbridge_agent(self):
        self.config.update({
            'DEFAULT': {
                'interface_driver': ('neutron.agent.linux.interface.'
                                     'BridgeInterfaceDriver'),
            }
        })

    def _generate_external_bridge(self):
        return utils.get_rand_device_name(prefix='br-ex')

    def get_external_bridge(self):
        return self.config.DEFAULT.external_network_bridge

    def _generate_namespace_suffix(self):
        return utils.get_rand_name(prefix='test')
