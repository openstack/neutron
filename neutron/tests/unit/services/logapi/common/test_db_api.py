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

import copy
from unittest import mock

from neutron_lib import constants as const
from neutron_lib import context
from neutron_lib.db import api as n_db_api
from neutron_lib.plugins import directory
from neutron_lib.services.logapi import constants as log_const
from neutron_lib.utils import net as net_utils
from oslo_utils import uuidutils

from neutron.objects.logapi import logging_resource as log_object
from neutron.services.logapi.common import db_api
from neutron.services.logapi.common import validators
from neutron.services.logapi.rpc import server as server_rpc
from neutron.tests.unit.extensions import test_securitygroup as test_sg


def _create_log(context, project_id, resource_id=None,
                target_id=None, event='ALL', enabled=True,):

    log_data = {
        'id': uuidutils.generate_uuid(),
        'name': 'test',
        'resource_type': 'security_group',
        'project_id': project_id,
        'event': event,
        'enabled': enabled}
    if resource_id:
        log_data['resource_id'] = resource_id
    if target_id:
        log_data['target_id'] = target_id
    with n_db_api.CONTEXT_WRITER.using(context):
        _log_obj = log_object.Log(context, **log_data)
        _log_obj.create()
    return _log_obj


class LoggingDBApiTestCase(test_sg.SecurityGroupDBTestCase):

    def setUp(self):
        super(LoggingDBApiTestCase, self).setUp()
        self.context = context.get_admin_context()
        self.sg_id, self.port_id, self._tenant_id = self._create_sg_and_port()
        self.context.tenant_id = self._tenant_id

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
        log = _create_log(self.context, self._tenant_id,
                          target_id=self.port_id)
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[log]):
            self.assertEqual(
                [log], db_api.get_logs_bound_port(self.context, self.port_id))

            # Test get log objects with required resource type
            calls = [mock.call(self.context, project_id=self._tenant_id,
                               resource_type=log_const.SECURITY_GROUP,
                               enabled=True)]
            log_object.Log.get_objects.assert_has_calls(calls)

    def test_get_logs_not_bound_port(self):
        fake_sg_id = uuidutils.generate_uuid()
        log = _create_log(self.context, self._tenant_id,
                          resource_id=fake_sg_id)
        with mock.patch.object(log_object.Log, 'get_objects',
                               return_value=[log]):
            self.assertEqual(
                [], db_api.get_logs_bound_port(self.context, self.port_id))

            # Test get log objects with required resource type
            calls = [mock.call(self.context, project_id=self._tenant_id,
                               resource_type=log_const.SECURITY_GROUP,
                               enabled=True)]
            log_object.Log.get_objects.assert_has_calls(calls)

    def test_get_logs_bound_sg(self):
        with self.network() as network, \
                self.subnet(network=network) as subnet, \
                self.port(subnet=subnet) as p1, \
                self.port(subnet=subnet, security_groups=[self.sg_id]) as p2:

            log = _create_log(self.context, self._tenant_id)
            log_sg = _create_log(self.context, self._tenant_id,
                                 resource_id=self.sg_id)
            log_port_no_sg = _create_log(self.context, self._tenant_id,
                                         target_id=p1['port']['id'])
            log_port_sg = _create_log(self.context, self._tenant_id,
                                      target_id=p2['port']['id'])
            self.assertEqual(
                [log, log_sg, log_port_sg],
                db_api.get_logs_bound_sg(self.context, sg_id=self.sg_id,
                                         project_id=self._tenant_id))
            self.assertEqual(
                [log_sg, log_port_sg],
                db_api.get_logs_bound_sg(self.context, sg_id=self.sg_id,
                                         project_id=self._tenant_id,
                                         exclusive=True))
            self.assertEqual(
                [log_port_no_sg],
                db_api.get_logs_bound_sg(
                    self.context, project_id=self._tenant_id,
                    port_id=p1['port']['id']))
            self.assertEqual(
                [log_port_sg],
                db_api.get_logs_bound_sg(
                    self.context, project_id=self._tenant_id,
                    port_id=p2['port']['id']))

    def test_get_logs_not_bound_sg(self):
        with self.network() as network, \
                self.subnet(network), \
                self.security_group() as sg:
            sg2_id = sg['security_group']['id']
            res = self._create_port(
                self.fmt, network['network']['id'],
                security_groups=[sg2_id])
            port2_id = self.deserialize(self.fmt, res)['port']['id']
            log = _create_log(self.context, self._tenant_id,
                              target_id=port2_id)
            with mock.patch.object(log_object.Log, 'get_objects',
                                   return_value=[log]):
                self.assertEqual(
                    [], db_api.get_logs_bound_sg(
                        self.context, self.sg_id, project_id=self._tenant_id))

                # Test get log objects with required resource type
                calls = [mock.call(self.context, project_id=self._tenant_id,
                                   resource_type=log_const.SECURITY_GROUP,
                                   enabled=True)]
                log_object.Log.get_objects.assert_has_calls(calls)

    def test__get_ports_being_logged(self):
        log1 = _create_log(self.context, self._tenant_id,
                           target_id=self.port_id)
        log2 = _create_log(self.context, self._tenant_id,
                           resource_id=self.sg_id)
        log3 = _create_log(self.context, self._tenant_id,
                           target_id=self.port_id, resource_id=self.sg_id)
        log4 = _create_log(self.context, self._tenant_id)
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
        log = _create_log(self.context, self._tenant_id)
        with mock.patch.object(
                validators, 'validate_log_type_for_port', return_value=False):
            ports_log = db_api._get_ports_being_logged(self.context, log)
        self.assertEqual([], ports_log)


class LoggingRpcCallbackTestCase(test_sg.SecurityGroupDBTestCase):

    def setUp(self):
        super(LoggingRpcCallbackTestCase, self).setUp()
        plugin = directory.get_plugin()
        mock.patch.object(
            plugin, 'get_default_security_group_rules',
            return_value=copy.deepcopy(
                test_sg.RULES_TEMPLATE_FOR_CUSTOM_SG)).start()
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
            log = _create_log(self.context, self._tenant_id, resource_id=sg_id)
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
                                 'ethertype': 'IPv4',
                                 'security_group_id': sg_id},
                                {'direction': 'egress',
                                 'ethertype': 'IPv6',
                                 'security_group_id': sg_id},
                                {'direction': 'ingress',
                                 'ethertype': 'IPv4',
                                 'port_range_max': 22,
                                 'port_range_min': 22,
                                 'protocol': 'tcp',
                                 'security_group_id': sg_id},
                                {'direction': 'egress',
                                 'ethertype': 'IPv4',
                                 'protocol': 'tcp',
                                 'dest_ip_prefix':
                                     net_utils.AuthenticIPNetwork(
                                         '10.0.0.1/32'),
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
            log = _create_log(self.context, tenant_id)
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
                                     'ethertype': 'IPv4',
                                     'security_group_id': sg_id},
                                    {'direction': 'egress',
                                     'ethertype': 'IPv6',
                                     'security_group_id': sg_id},
                                    {'direction': 'ingress',
                                     'ethertype': 'IPv4',
                                     'port_range_max': 13,
                                     'port_range_min': 11,
                                     'protocol': 'tcp',
                                     'source_ip_prefix':
                                         net_utils.AuthenticIPNetwork(
                                             '10.0.0.1/32'),
                                     'security_group_id': sg_id},
                                    {'direction': 'egress',
                                     'ethertype': 'IPv4',
                                     'protocol': 'icmp',
                                     'security_group_id': sg_id}]
                            }],
                            'project_id': tenant_id
                        }]

                        self.assertEqual(expected, ports_log)
                    self._delete('ports', port_id)
