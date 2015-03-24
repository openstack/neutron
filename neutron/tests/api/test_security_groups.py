# Copyright 2013 OpenStack Foundation
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

import six
from tempest_lib.common.utils import data_utils

from neutron.tests.api import base_security_groups as base
from neutron.tests.tempest import config
from neutron.tests.tempest import test

CONF = config.CONF


class SecGroupTest(base.BaseSecGroupTest):

    _tenant_network_cidr = CONF.network.tenant_network_cidr

    @classmethod
    def resource_setup(cls):
        super(SecGroupTest, cls).resource_setup()
        if not test.is_extension_enabled('security-group', 'network'):
            msg = "security-group extension not enabled."
            raise cls.skipException(msg)

    def _create_verify_security_group_rule(self, sg_id, direction,
                                           ethertype, protocol,
                                           port_range_min,
                                           port_range_max,
                                           remote_group_id=None,
                                           remote_ip_prefix=None):
        # Create Security Group rule with the input params and validate
        # that SG rule is created with the same parameters.
        rule_create_body = self.client.create_security_group_rule(
            security_group_id=sg_id,
            direction=direction,
            ethertype=ethertype,
            protocol=protocol,
            port_range_min=port_range_min,
            port_range_max=port_range_max,
            remote_group_id=remote_group_id,
            remote_ip_prefix=remote_ip_prefix
        )

        sec_group_rule = rule_create_body['security_group_rule']
        self.addCleanup(self._delete_security_group_rule,
                        sec_group_rule['id'])

        expected = {'direction': direction, 'protocol': protocol,
                    'ethertype': ethertype, 'port_range_min': port_range_min,
                    'port_range_max': port_range_max,
                    'remote_group_id': remote_group_id,
                    'remote_ip_prefix': remote_ip_prefix}
        for key, value in six.iteritems(expected):
            self.assertEqual(value, sec_group_rule[key],
                             "Field %s of the created security group "
                             "rule does not match with %s." %
                             (key, value))

    @test.attr(type='smoke')
    @test.idempotent_id('e30abd17-fef9-4739-8617-dc26da88e686')
    def test_list_security_groups(self):
        # Verify the that security group belonging to tenant exist in list
        body = self.client.list_security_groups()
        security_groups = body['security_groups']
        found = None
        for n in security_groups:
            if (n['name'] == 'default'):
                found = n['id']
        msg = "Security-group list doesn't contain default security-group"
        self.assertIsNotNone(found, msg)

    @test.attr(type='smoke')
    @test.idempotent_id('bfd128e5-3c92-44b6-9d66-7fe29d22c802')
    def test_create_list_update_show_delete_security_group(self):
        group_create_body, name = self._create_security_group()

        # List security groups and verify if created group is there in response
        list_body = self.client.list_security_groups()
        secgroup_list = list()
        for secgroup in list_body['security_groups']:
            secgroup_list.append(secgroup['id'])
        self.assertIn(group_create_body['security_group']['id'], secgroup_list)
        # Update the security group
        new_name = data_utils.rand_name('security-')
        new_description = data_utils.rand_name('security-description')
        update_body = self.client.update_security_group(
            group_create_body['security_group']['id'],
            name=new_name,
            description=new_description)
        # Verify if security group is updated
        self.assertEqual(update_body['security_group']['name'], new_name)
        self.assertEqual(update_body['security_group']['description'],
                         new_description)
        # Show details of the updated security group
        show_body = self.client.show_security_group(
            group_create_body['security_group']['id'])
        self.assertEqual(show_body['security_group']['name'], new_name)
        self.assertEqual(show_body['security_group']['description'],
                         new_description)

    @test.attr(type='smoke')
    @test.idempotent_id('cfb99e0e-7410-4a3d-8a0c-959a63ee77e9')
    def test_create_show_delete_security_group_rule(self):
        group_create_body, _ = self._create_security_group()

        # Create rules for each protocol
        protocols = ['tcp', 'udp', 'icmp']
        for protocol in protocols:
            rule_create_body = self.client.create_security_group_rule(
                security_group_id=group_create_body['security_group']['id'],
                protocol=protocol,
                direction='ingress',
                ethertype=self.ethertype
            )

            # Show details of the created security rule
            show_rule_body = self.client.show_security_group_rule(
                rule_create_body['security_group_rule']['id']
            )
            create_dict = rule_create_body['security_group_rule']
            for key, value in six.iteritems(create_dict):
                self.assertEqual(value,
                                 show_rule_body['security_group_rule'][key],
                                 "%s does not match." % key)

            # List rules and verify created rule is in response
            rule_list_body = self.client.list_security_group_rules()
            rule_list = [rule['id']
                         for rule in rule_list_body['security_group_rules']]
            self.assertIn(rule_create_body['security_group_rule']['id'],
                          rule_list)

    @test.attr(type='smoke')
    @test.idempotent_id('87dfbcf9-1849-43ea-b1e4-efa3eeae9f71')
    def test_create_security_group_rule_with_additional_args(self):
        """Verify security group rule with additional arguments works.

        direction:ingress, ethertype:[IPv4/IPv6],
        protocol:tcp, port_range_min:77, port_range_max:77
        """
        group_create_body, _ = self._create_security_group()
        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 77
        port_range_max = 77
        self._create_verify_security_group_rule(sg_id, direction,
                                                self.ethertype, protocol,
                                                port_range_min,
                                                port_range_max)

    @test.attr(type='smoke')
    @test.idempotent_id('c9463db8-b44d-4f52-b6c0-8dbda99f26ce')
    def test_create_security_group_rule_with_icmp_type_code(self):
        """Verify security group rule for icmp protocol works.

        Specify icmp type (port_range_min) and icmp code
        (port_range_max) with different values. A separate testcase
        is added for icmp protocol as icmp validation would be
        different from tcp/udp.
        """
        group_create_body, _ = self._create_security_group()

        sg_id = group_create_body['security_group']['id']
        direction = 'ingress'
        protocol = 'icmp'
        icmp_type_codes = [(3, 2), (3, 0), (8, 0), (0, 0), (11, None)]
        for icmp_type, icmp_code in icmp_type_codes:
            self._create_verify_security_group_rule(sg_id, direction,
                                                    self.ethertype, protocol,
                                                    icmp_type, icmp_code)

    @test.attr(type='smoke')
    @test.idempotent_id('c2ed2deb-7a0c-44d8-8b4c-a5825b5c310b')
    def test_create_security_group_rule_with_remote_group_id(self):
        # Verify creating security group rule with remote_group_id works
        sg1_body, _ = self._create_security_group()
        sg2_body, _ = self._create_security_group()

        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'udp'
        port_range_min = 50
        port_range_max = 55
        remote_id = sg2_body['security_group']['id']
        self._create_verify_security_group_rule(sg_id, direction,
                                                self.ethertype, protocol,
                                                port_range_min,
                                                port_range_max,
                                                remote_group_id=remote_id)

    @test.attr(type='smoke')
    @test.idempotent_id('16459776-5da2-4634-bce4-4b55ee3ec188')
    def test_create_security_group_rule_with_remote_ip_prefix(self):
        # Verify creating security group rule with remote_ip_prefix works
        sg1_body, _ = self._create_security_group()

        sg_id = sg1_body['security_group']['id']
        direction = 'ingress'
        protocol = 'tcp'
        port_range_min = 76
        port_range_max = 77
        ip_prefix = self._tenant_network_cidr
        self._create_verify_security_group_rule(sg_id, direction,
                                                self.ethertype, protocol,
                                                port_range_min,
                                                port_range_max,
                                                remote_ip_prefix=ip_prefix)

    @test.attr(type='smoke')
    @test.idempotent_id('0a307599-6655-4220-bebc-fd70c64f2290')
    def test_create_security_group_rule_with_protocol_integer_value(self):
        # Verify creating security group rule with the
        # protocol as integer value
        # arguments : "protocol": 17
        group_create_body, _ = self._create_security_group()
        direction = 'ingress'
        protocol = 17
        security_group_id = group_create_body['security_group']['id']
        rule_create_body = self.client.create_security_group_rule(
            security_group_id=security_group_id,
            direction=direction,
            protocol=protocol
        )
        sec_group_rule = rule_create_body['security_group_rule']
        self.assertEqual(sec_group_rule['direction'], direction)
        self.assertEqual(int(sec_group_rule['protocol']), protocol)


class SecGroupIPv6Test(SecGroupTest):
    _ip_version = 6
    _tenant_network_cidr = CONF.network.tenant_network_v6_cidr
