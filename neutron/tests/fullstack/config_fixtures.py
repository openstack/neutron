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

import os.path
import tempfile

import fixtures
import six

from neutron.common import constants
from neutron.tests import base
from neutron.tests.common import helpers as c_helpers
from neutron.tests.functional.agent.linux import helpers


class ConfigDict(base.AttributeDict):
    def update(self, other):
        self.convert_to_attr_dict(other)
        super(ConfigDict, self).update(other)

    def convert_to_attr_dict(self, other):
        """Convert nested dicts to AttributeDict.

        :param other: dictionary to be directly modified.
        """
        for key, value in other.iteritems():
            if isinstance(value, dict):
                if not isinstance(value, base.AttributeDict):
                    other[key] = base.AttributeDict(value)
                self.convert_to_attr_dict(value)


class ConfigFileFixture(fixtures.Fixture):
    """A fixture that knows how to translate configurations to files.

    :param base_filename: the filename to use on disk.
    :param config: a ConfigDict instance.
    :param temp_dir: an existing temporary directory to use for storage.
    """

    def __init__(self, base_filename, config, temp_dir):
        super(ConfigFileFixture, self).__init__()
        self.base_filename = base_filename
        self.config = config
        self.temp_dir = temp_dir

    def setUp(self):
        super(ConfigFileFixture, self).setUp()
        config_parser = self.dict_to_config_parser(self.config)
        # Need to randomly generate a unique folder to put the file in
        self.filename = os.path.join(self.temp_dir, self.base_filename)
        with open(self.filename, 'w') as f:
            config_parser.write(f)
            f.flush()

    def dict_to_config_parser(self, config_dict):
        config_parser = six.moves.configparser.SafeConfigParser()
        for section, section_dict in six.iteritems(config_dict):
            if section != 'DEFAULT':
                config_parser.add_section(section)
            for option, value in six.iteritems(section_dict):
                config_parser.set(section, option, value)
        return config_parser


class ConfigFixture(fixtures.Fixture):
    """A fixture that holds an actual Neutron configuration.

    Note that 'self.config' is intended to only be updated once, during
    the constructor, so if this fixture is re-used (setUp is called twice),
    then the dynamic configuration values won't change. The correct usage
    is initializing a new instance of the class.
    """
    def __init__(self, temp_dir, base_filename):
        self.config = ConfigDict()
        self.temp_dir = temp_dir
        self.base_filename = base_filename

    def setUp(self):
        super(ConfigFixture, self).setUp()
        cfg_fixture = ConfigFileFixture(
            self.base_filename, self.config, self.temp_dir)
        self.useFixture(cfg_fixture)
        self.filename = cfg_fixture.filename


class NeutronConfigFixture(ConfigFixture):

    def __init__(self, temp_dir, connection):
        super(NeutronConfigFixture, self).__init__(
            temp_dir, base_filename='neutron.conf')

        self.config.update({
            'DEFAULT': {
                'host': self._generate_host(),
                'state_path': self._generate_state_path(temp_dir),
                'bind_port': self._generate_port(),
                'api_paste_config': self._generate_api_paste(),
                'policy_file': self._generate_policy_json(),
                'core_plugin': 'neutron.plugins.ml2.plugin.Ml2Plugin',
                'rabbit_userid': 'stackrabbit',
                'rabbit_password': 'secretrabbit',
                'rabbit_hosts': '127.0.0.1',
                'auth_strategy': 'noauth',
                'verbose': 'True',
                'debug': 'True',
            },
            'database': {
                'connection': connection,
            }
        })

    def _generate_host(self):
        return base.get_rand_name(prefix='host-')

    def _generate_state_path(self, temp_dir):
        # Assume that temp_dir will be removed by the caller
        self.state_path = tempfile.mkdtemp(prefix='state_path', dir=temp_dir)
        return self.state_path

    def _generate_port(self):
        """Get a free TCP port from the Operating System and return it.

        This might fail if some other process occupies this port after this
        function finished but before the neutron-server process started.
        """
        return str(helpers.get_free_namespace_port())

    def _generate_api_paste(self):
        return c_helpers.find_sample_file('api-paste.ini')

    def _generate_policy_json(self):
        return c_helpers.find_sample_file('policy.json')


class ML2ConfigFixture(ConfigFixture):

    def __init__(self, temp_dir):
        super(ML2ConfigFixture, self).__init__(
            temp_dir, base_filename='ml2_conf.ini')

        self.config.update({
            'ml2': {
                'tenant_network_types': 'vlan',
                'mechanism_drivers': 'openvswitch',
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
            'ovs': {
                'enable_tunneling': 'False',
                'local_ip': '127.0.0.1',
                'bridge_mappings': self._generate_bridge_mappings(),
                'integration_bridge': self._generate_integration_bridge(),
            }
        })

    def _generate_bridge_mappings(self):
        return ('physnet1:%s' %
                base.get_rand_name(
                    prefix='br-eth',
                    max_length=constants.DEVICE_NAME_MAX_LEN))

    def _generate_integration_bridge(self):
        return base.get_rand_name(prefix='br-int',
                                  max_length=constants.DEVICE_NAME_MAX_LEN)
