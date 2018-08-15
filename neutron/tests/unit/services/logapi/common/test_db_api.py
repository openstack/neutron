# Copyright (c) 2017 Fujitsu Limited
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

import mock
from neutron_lib import constants as const
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.common import utils
from neutron.objects.logapi import logging_resource as log_object
from neutron.services.logapi.common import constants as log_const
from neutron.services.logapi.common import db_api
from neutron.services.logapi.common import validators
from neutron.services.logapi.rpc import server as server_rpc
from neutron.tests.unit.extensions import test_securitygroup as test_sg


def _create_log(tenant_id, resource_id=None,
                target_id=None, event='ALL', enabled=True,):

    log_data = {
        'id': uuidutils.generate_uuid(),
        'name': 'test',
        'resource_type': 'security_group',
        'project_id': tenant_id,
        'event': event,
        'enabled': enabled}
    if resource_id:
        log_data['resource_id'] = resource_id
    if target_id:
        log_data['target_id'] = target_id
    return log_object.Log(**log_data)


class LoggingDBApiTestCase(test_sg.SecurityGroupDBTestCase):

    def setUp(self):
        super(LoggingDBApiTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.sg_id, self.port_id, self.tenant_id = self._create_sg_and_port()
        self.context.tenant_id = self.tenant_id

    def _create_sg_and_port(self):
        with self.network() as network, \
                self.subnet(network), \
                self.security_group() as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']

            res = self._create_port(
                self.fmt, network['network']['id'],
                security_groups=[sg_id])
            ports_rest = self.deserialize(self.fmt, res)
            port_id = ports_rest['port']['id']
        return sg_id, port_id, tenant_id

    def test_get_logs_bound_port(self):
        log = _create_log(target_id=self.port_id, tenant_id=self.tenant_id)
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[log]):
            self.assertEqual(
                [log], db_api.get_logs_bound_port(self.context, self.port_id))

            # Test get log objects with required resource type
            calls = [mock.call(self.context, project_id=self.tenant_id,
                               resource_type=log_const.SECURITY_GROUP,
                               enabled=True)]
            log_object.Log.get_objects.assert_has_calls(calls)

    def test_get_logs_not_bound_port(self):
        fake_sg_id = uuidutils.generate_uuid()
        log = _create_log(resource_id=fake_sg_id, tenant_id=self.tenant_id)
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[log]):
            self.assertEqual(
                [], db_api.get_logs_bound_port(self.context, self.port_id))

            # Test get log objects with required resource type
            calls = [mock.call(self.context, project_id=self.tenant_id,
                               resource_type=log_const.SECURITY_GROUP,
                               enabled=True)]
            log_object.Log.get_objects.assert_has_calls(calls)

    def test_get_logs_bound_sg(self):
        log = _create_log(resource_id=self.sg_id, tenant_id=self.tenant_id)
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[log]):
            self.assertEqual(
                [log], db_api.get_logs_bound_sg(self.context, self.sg_id))

            # Test get log objects with required resource type
            calls = [mock.call(self.context, project_id=self.tenant_id,
                               resource_type=log_const.SECURITY_GROUP,
                               enabled=True)]
            log_object.Log.get_objects.assert_has_calls(calls)

    def test_get_logs_not_bound_sg(self):
        with self.network() as network, \
                self.subnet(network), \
                self.security_group() as sg:
            sg2_id = sg['security_group']['id']
            res = self._create_port(
                self.fmt, network['network']['id'],
                security_groups=[sg2_id])
            port2_id = self.deserialize(self.fmt, res)['port']['id']
            log = _create_log(target_id=port2_id, tenant_id=self.tenant_id)
            with mock.patch.object(log_object.Log, 'get_objects',
                                   return_value=[log]):
                self.assertEqual(
                    [], db_api.get_logs_bound_sg(self.context, self.sg_id))

                # Test get log objects with required resource type
                calls = [mock.call(self.context, project_id=self.tenant_id,
                                   resource_type=log_const.SECURITY_GROUP,
                                   enabled=True)]
                log_object.Log.get_objects.assert_has_calls(calls)

    def test__get_ports_being_logged(self):
        log1 = _create_log(target_id=self.port_id,
                           tenant_id=self.tenant_id)
        log2 = _create_log(resource_id=self.sg_id,
                           tenant_id=self.tenant_id)
        log3 = _create_log(target_id=self.port_id,
                           resource_id=self.tenant_id,
                           tenant_id=self.tenant_id)
        log4 = _create_log(tenant_id=self.tenant_id)
        with mock.patch.object(
                validators, 'validate_log_type_for_port', return_value=True):
            ports_log1 = db_api._get_ports_being_logged(self.context, log1)
            ports_log2 = db_api._get_ports_being_logged(self.context, log2)
            ports_log3 = db_api._get_ports_being_logged(self.context, log3)
            ports_log4 = db_api._get_ports_being_logged(self.context, log4)

            self.assertEqual([self.port_id], ports_log1)
            self.assertEqual([self.port_id], ports_log2)
            self.assertEqual([self.port_id], ports_log3)
            self.assertEqual([self.port_id], ports_log4)

    def test__get_ports_being_logged_not_supported_log_type(self):
        log = _create_log(tenant_id=self.tenant_id)
        with mock.patch.object(
                validators, 'validate_log_type_for_port', return_value=False):
            ports_log = db_api._get_ports_being_logged(self.context, log)
        self.assertEqual([], ports_log)


class LoggingRpcCallbackTestCase(test_sg.SecurityGroupDBTestCase):

    def setUp(self):
        super(LoggingRpcCallbackTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.rpc_callback = server_rpc.LoggingApiSkeleton()

    def test_get_sg_log_info_for_create_or_update_log(self):
        with self.network() as network, \
                self.subnet(network), \
                self.security_group() as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']
            rule1 = self._build_security_group_rule(
                sg_id,
                'ingress', const.PROTO_NAME_TCP, '22', '22',
            )
            rule2 = self._build_security_group_rule(
                sg_id,
                'egress', const.PROTO_NAME_TCP,
                remote_ip_prefix='10.0.0.1',
            )
            rules = {
                'security_group_rules': [rule1['security_group_rule'],
                                         rule2['security_group_rule']]}
            self._create_security_group_rule(self.fmt, rules)
            res = self._create_port(
                self.fmt, network['network']['id'],
                security_groups=[sg_id])
            ports_rest = self.deserialize(self.fmt, res)
            port_id = ports_rest['port']['id']
            log = _create_log(resource_id=sg_id, tenant_id=tenant_id)
            with mock.patch.object(
                    server_rpc,
                    'get_rpc_method',
                    return_value=server_rpc.get_sg_log_info_for_log_resources
            ):
                with mock.patch.object(validators,
                                       'validate_log_type_for_port',
                                       return_value=True):
                    ports_log = (
                        self.rpc_callback.get_sg_log_info_for_log_resources(
                            self.context,
                            resource_type=log_const.SECURITY_GROUP,
                            log_resources=[log])
                    )
                    expected = [{
                        'event': log.event,
                        'id': log.id,
                        'ports_log': [{
                            'port_id': port_id,
                            'security_group_rules': [
                                {'direction': 'egress',
                                 'ethertype': u'IPv4',
                                 'security_group_id': sg_id},
                                {'direction': 'egress',
                                 'ethertype': u'IPv6',
                                 'security_group_id': sg_id},
                                {'direction': 'ingress',
                                 'ethertype': u'IPv4',
                                 'port_range_max': 22,
                                 'port_range_min': 22,
                                 'protocol': u'tcp',
                                 'security_group_id': sg_id},
                                {'direction': 'egress',
                                 'ethertype': u'IPv4',
                                 'protocol': u'tcp',
                                 'dest_ip_prefix':
                                     utils.AuthenticIPNetwork('10.0.0.1/32'),
                                 'security_group_id': sg_id}]
                        }],
                        'project_id': tenant_id
                    }]
                    self.assertEqual(expected, ports_log)
                self._delete('ports', port_id)

    def test_get_sg_log_info_for_port_added_event(self):
        with self.network() as network, \
                self.subnet(network), \
                self.security_group() as sg:
            sg_id = sg['security_group']['id']
            tenant_id = sg['security_group']['tenant_id']
            rule1 = self._build_security_group_rule(
                sg_id,
                'ingress', const.PROTO_NAME_TCP, '11', '13',
                remote_ip_prefix='10.0.0.1',
            )
            rule2 = self._build_security_group_rule(
                sg_id,
                'egress', const.PROTO_NAME_ICMP,
            )
            rules = {
                'security_group_rules': [rule1['security_group_rule'],
                                         rule2['security_group_rule']]}
            self._create_security_group_rule(self.fmt, rules)
            res = self._create_port(
                self.fmt, network['network']['id'],
                security_groups=[sg_id],
                tenant_id=tenant_id
            )
            ports_rest = self.deserialize(self.fmt, res)
            port_id = ports_rest['port']['id']
            log = _create_log(tenant_id=tenant_id)
            with mock.patch.object(
                    log_object.Log, 'get_objects', return_value=[log]):
                with mock.patch.object(
                        server_rpc,
                        'get_rpc_method',
                        return_value=server_rpc.get_sg_log_info_for_port
                ):
                    with mock.patch.object(
                            validators,
                            'validate_log_type_for_port',
                            return_value=True):
                        ports_log = (
                            self.rpc_callback.get_sg_log_info_for_port(
                                self.context,
                                resource_type=log_const.SECURITY_GROUP,
                                port_id=port_id)
                        )
                        expected = [{
                            'event': log.event,
                            'id': log.id,
                            'ports_log': [{
                                'port_id': port_id,
                                'security_group_rules': [
                                    {'direction': 'egress',
                                     'ethertype': u'IPv4',
                                     'security_group_id': sg_id},
                                    {'direction': 'egress',
                                     'ethertype': u'IPv6',
                                     'security_group_id': sg_id},
                                    {'direction': 'ingress',
                                     'ethertype': u'IPv4',
                                     'port_range_max': 13,
                                     'port_range_min': 11,
                                     'protocol': u'tcp',
                                     'source_ip_prefix':
                                         utils.AuthenticIPNetwork(
                                             '10.0.0.1/32'),
                                     'security_group_id': sg_id},
                                    {'direction': 'egress',
                                     'ethertype': u'IPv4',
                                     'protocol': u'icmp',
                                     'security_group_id': sg_id}]
                            }],
                            'project_id': tenant_id
                        }]

                        self.assertEqual(expected, ports_log)
                    self._delete('ports', port_id)
