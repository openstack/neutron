# Copyright 2025 Red Hat, Inc.
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

from ovs import stream
from unittest import mock

from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf
from neutron.services.bgp import ovn
from neutron.tests import base


class OvnNbIdlTestCase(base.BaseTestCase):
    def setUp(self):
        super().setUp()
        ovn_conf.register_opts()
        ovn_conf.cfg.CONF.set_override(
            'ovn_nb_private_key', 'nb-private-key', 'ovn')
        ovn_conf.cfg.CONF.set_override(
            'ovn_nb_certificate', 'nb-certificate', 'ovn')
        ovn_conf.cfg.CONF.set_override(
            'ovn_nb_ca_cert', 'nb-ca-cert', 'ovn')
        mock.patch(
            'ovsdbapp.backend.ovs_idl.idlutils.get_schema_helper').start()
        mock.patch('ovs.db.idl.Idl.__init__').start()

    def test_init_with_ssl(self):
        """Check the SSL is configured correctly"""
        connection = "ssl:127.0.0.1:6640"
        ovn.OvnNbIdl(connection)
        self.assertEqual('nb-ca-cert', stream.Stream._SSL_ca_cert_file)
        self.assertEqual('nb-certificate', stream.Stream._SSL_certificate_file)
        self.assertEqual('nb-private-key', stream.Stream._SSL_private_key_file)
