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

from unittest import mock

from neutron_lib import constants as n_const
from neutron_lib import context
from neutron_lib import exceptions
from neutron_lib.services.logapi import constants as log_const

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.services.logapi.common import exceptions as log_exc
from neutron.tests.functional import base as functional_base


class LogApiTestCaseBase(functional_base.TestOVNFunctionalBase):
    def setUp(self):
        super().setUp()
        self.log_driver = self.mech_driver.log_driver
        self._check_is_supported()
        self.ctxt = context.Context('admin', self._tenant_id)

    def _check_is_supported(self):
        if not self.log_driver.network_logging_supported(self.nb_api):
            self.skipTest("The current OVN version does not offer support "
                          "for neutron network log functionality.")
        self.assertIsNotNone(self.log_plugin)

    def _log_data(self, sg_id=None, port_id=None, enabled=True):
        log_data = {'project_id': self.ctxt.project_id,
                    'resource_type': 'security_group',
                    'description': 'test net log',
                    'name': 'logme',
                    'enabled': enabled,
                    'event': log_const.ALL_EVENT}
        if sg_id:
            log_data['resource_id'] = sg_id
        if port_id:
            log_data['target_id'] = port_id
        return {'log': log_data}


class LogApiTestCaseSimple(LogApiTestCaseBase):
    def test_basic_get(self):
        log_obj = self.log_plugin.create_log(self.ctxt, self._log_data())
        self.assertIsNotNone(log_obj)
        log_obj_get = self.log_plugin.get_log(self.ctxt, log_obj['id'])
        self.assertEqual(log_obj, log_obj_get)
        log_obj2 = self.log_plugin.create_log(self.ctxt, self._log_data())
        self.assertIsNotNone(log_obj2)
        log_objs_get = self.log_plugin.get_logs(self.ctxt)
        log_objs_ids = {x['id'] for x in log_objs_get}
        self.assertEqual({log_obj['id'], log_obj2['id']}, log_objs_ids)

    def test_log_ovn_unsupported(self):
        with mock.patch.object(self.log_driver, 'network_logging_supported',
                        return_value=False) as supported_mock:
            log_data = {'log': {'resource_type': 'security_group',
                                'enabled': True}}
            self.assertRaises(exceptions.DriverCallError,
                              self.log_plugin.create_log,
                              self.ctxt, log_data)
            supported_mock.assert_called_once()


class LogApiTestCaseComplex(LogApiTestCaseBase):
    def setUp(self):
        super().setUp()
        self._prepare_env()

    def _prepare_env(self):
        self.net = self._create_network(
            self.fmt, 'private', admin_state_up=True).json['network']['id']
        self.subnet = self._create_subnet(
            self.fmt, self.net, '10.0.0.0/24', enable_dhcp=False).json[
            'subnet']['id']

        self.sg1 = self._create_security_group('test_sg1_ssh')
        self.sg2 = self._create_security_group('test_sg2_http')
        self.sg3 = self._create_security_group('test_sg3_telnet_ssh')
        self.sg1rs = [self._create_security_group_rule(self.sg1, 22)]
        self.sg2rs = [self._create_security_group_rule(self.sg2, 80)]
        self.sg3rs = [self._create_security_group_rule(self.sg3, 23),
                      self._create_security_group_rule(self.sg3, 22)]
        self.sgs = [self.sg1, self.sg2, self.sg3]
        self.sgrs = self.sg1rs + self.sg2rs + self.sg3rs

        self.port1_sgs = [self.sg1]
        self.port1_sgrs = self.sg1rs
        self.port1 = self._create_port(self.fmt, self.net,
                                       security_groups=self.port1_sgs)
        self.port2_sgs = [self.sg2, self.sg3]
        self.port2_sgrs = self.sg2rs + self.sg3rs
        self.port2 = self._create_port(self.fmt, self.net,
                                       security_groups=self.port2_sgs)
        self.port3_sgs = [self.sg1, self.sg3]
        self.port3_sgrs = self.sg1rs + self.sg3rs
        self.port3 = self._create_port(self.fmt, self.net,
                                       security_groups=self.port3_sgs)

    def _create_port(self, name, net_id, security_groups):
        data = {'port': {'name': name,
                         'network_id': net_id,
                         'security_groups': security_groups}}
        req = self.new_create_request('ports', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['port']['id']

    def _create_security_group(self, name):
        data = {'security_group': {'name': name}}
        req = self.new_create_request('security-groups', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['security_group']['id']

    def _create_security_group_rule(self, sg_id, tcp_port):
        data = {'security_group_rule': {'security_group_id': sg_id,
                                        'direction': 'ingress',
                                        'protocol': n_const.PROTO_NAME_TCP,
                                        'ethertype': n_const.IPv4,
                                        'port_range_min': tcp_port,
                                        'port_range_max': tcp_port}}
        req = self.new_create_request('security-group-rules', data, self.fmt)
        res = req.get_response(self.api)
        return self.deserialize(self.fmt, res)['security_group_rule']['id']

    def _find_security_group_row_by_id(self, sg_id):
        for row in self.nb_api._tables['Port_Group'].rows.values():
            if row.name == utils.ovn_port_group_name(sg_id):
                return row

    def _find_security_group_rule_row_by_id(self, sgr_id):
        for row in self.nb_api._tables['ACL'].rows.values():
            if (row.external_ids.get(
                    ovn_const.OVN_SG_RULE_EXT_ID_KEY) == sgr_id):
                return row

    def _check_acl_log(self, sgr, is_enabled=True):
        acl = self._find_security_group_rule_row_by_id(sgr)
        self.assertIsNotNone(acl)
        self.assertEqual(is_enabled, acl.log)
        if hasattr(acl, "label"):
            # Here we compare if there is a name because the log can be
            # disabled but disabling a log would not take out the properties
            # attached to it.
            if acl.name:
                self.assertNotEqual(0, acl.label)
                self.assertEqual("true", acl.options.get("log-related"))
            else:
                self.assertEqual(0, acl.label)
                self.assertIsNone(acl.options.get("log-related"))
        return acl

    def _check_acl_log_drop(self, is_enabled=True):
        acls = self.nb_api.get_port_group(
            ovn_const.OVN_DROP_PORT_GROUP_NAME).acls
        self.assertTrue(acls)
        for acl in acls:
            self.assertEqual(is_enabled, acl.log)
        return acls

    def _check_sgrs(self, sgrs=None, is_enabled=True):
        if not sgrs:
            sgrs = self.sgrs
        for sgr in sgrs:
            self._check_acl_log(sgr, is_enabled)

    def test_add_and_remove(self):
        self._check_sgrs(is_enabled=False)
        self.assertEqual([],
                         self.nb_api.meter_list().execute(check_error=True))

        log_obj = self.log_plugin.create_log(self.ctxt, self._log_data())
        for sgr in self.sgrs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj['id']), acl.name[0])
            meter = self.nb_api.meter_get(acl.meter[0]).execute(
                check_error=True)
            self.assertEqual([True], meter.fair)
            self.assertEqual('pktps', meter.unit)
            self.assertEqual(1, len(meter.bands))
            self.assertEqual({ovn_const.OVN_DEVICE_OWNER_EXT_ID_KEY:
                              log_const.LOGGING_PLUGIN}, meter.external_ids)

        self.log_plugin.delete_log(self.ctxt, log_obj['id'])
        self._check_sgrs(is_enabled=False)
        self.assertEqual([],
                         self.nb_api.meter_list().execute(check_error=True))

        log_objs = []
        for sg in self.sgs:
            log_data = self._log_data(sg_id=sg)
            log_objs.append(self.log_plugin.create_log(self.ctxt, log_data))
        self.assertEqual(len(log_objs),
                         len(self.log_plugin.get_logs(self.ctxt)))
        self._check_sgrs(is_enabled=True)

        # Attempt to delete non-existing row
        self.assertRaises(log_exc.LogResourceNotFound,
                          self.log_plugin.delete_log,
                          self.ctxt, log_obj['id'])

        self.log_plugin.delete_log(self.ctxt, log_objs[1]['id'])
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=True)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=True)

        self.log_plugin.delete_log(self.ctxt, log_objs[2]['id'])
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=True)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=False)

        self.log_plugin.delete_log(self.ctxt, log_objs[0]['id'])
        self.assertEqual([], self.log_plugin.get_logs(self.ctxt))
        self._check_sgrs(is_enabled=False)

        # Attempt to delete from empty table
        self.assertRaises(log_exc.LogResourceNotFound,
                          self.log_plugin.delete_log,
                          self.ctxt, log_objs[0]['id'])

    def test_update_all(self):
        # Note: only these fields are supported for update:
        # openstack network log set [-h] [--description <description>]
        # [--enable | --disable] [--name <name>] <network-log>

        log_data = self._log_data()
        log_obj = self.log_plugin.create_log(self.ctxt, log_data)
        self._check_sgrs()

        log_data['log']['name'] = 'logme-nay'
        log_data['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs(is_enabled=False)

        log_data['log']['name'] = 'logme-yay'
        log_data['log']['description'] = 'logs are a beautiful thing'
        log_data['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs()

    def test_update_one_sg(self):
        log_data = self._log_data(sg_id=self.sg2, enabled=False)
        log_obj = self.log_plugin.create_log(self.ctxt, log_data)
        self._check_sgrs(is_enabled=False)

        log_data['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj['id'], log_data)
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=True)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=False)

    def test_overlap_net_logs(self):
        log_data1 = self._log_data(sg_id=self.sg3, port_id=self.port3)
        log_obj1 = self.log_plugin.create_log(self.ctxt, log_data1)
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg2rs, is_enabled=False)
        self._check_sgrs(sgrs=self.sg3rs, is_enabled=True)

        log_data2 = self._log_data(port_id=self.port2)
        log_obj2 = self.log_plugin.create_log(self.ctxt, log_data2)
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)

        # port 2 uses sg2 and sg3. However, sg3 is in use by log_obj1
        # so only acls for 2 would be associated with log_obj2
        for sgr in self.sg2rs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj2['id']), acl.name[0])
        for sgr in self.sg3rs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj1['id']), acl.name[0])

        # Next, delete log_obj1 and make sure that lob_obj2 gets to
        # claim what it could not use before
        self.log_plugin.delete_log(self.ctxt, log_obj1['id'])
        self._check_sgrs(sgrs=self.sg1rs, is_enabled=False)
        for sgr in self.sg2rs + self.sg3rs:
            acl = self._check_acl_log(sgr)
            self.assertEqual(utils.ovn_name(log_obj2['id']), acl.name[0])

        # Delete log_obj2 and ensure that logs are off and meter is no
        # longer used
        self.log_plugin.delete_log(self.ctxt, log_obj2['id'])
        self._check_sgrs(is_enabled=False)
        self.assertEqual([],
                         self.nb_api.meter_list().execute(check_error=True))

    def _add_logs_then_remove(self, event1, event2, sg=None, sgrs=None):
        # Events were previously not correctly applied on ACLs. This test
        # ensures that each event log only the necessary acls
        drop_true_events = (log_const.DROP_EVENT, log_const.ALL_EVENT)
        accept_true_events = (log_const.ALL_EVENT, log_const.ACCEPT_EVENT)
        # Check there are no acls with their logging active
        self._check_sgrs(sgrs=sgrs, is_enabled=False)
        self._check_acl_log_drop(is_enabled=False)

        # Add first log object
        log_data1 = self._log_data(sg_id=sg)
        log_data1['log']['event'] = event1
        log_obj1 = self.log_plugin.create_log(self.ctxt, log_data1)
        self._check_acl_log_drop(is_enabled=event1 in drop_true_events)
        self._check_sgrs(sgrs=sgrs, is_enabled=event1 in accept_true_events)

        # Add second log object
        log_data2 = self._log_data(sg_id=sg)
        log_data2['log']['event'] = event2
        log_obj2 = self.log_plugin.create_log(self.ctxt, log_data2)
        self._check_acl_log_drop(is_enabled=(event1 in drop_true_events or
            event2 in drop_true_events))
        self._check_sgrs(sgrs=sgrs, is_enabled=(event1 in accept_true_events or
            event2 in accept_true_events))

        # Delete second log object
        self.log_plugin.delete_log(self.ctxt, log_obj2['id'])
        self._check_acl_log_drop(is_enabled=event1 in drop_true_events)
        self._check_sgrs(sgrs=sgrs, is_enabled=event1 in accept_true_events)

        # Delete first log object
        self.log_plugin.delete_log(self.ctxt, log_obj1['id'])
        self._check_sgrs(sgrs=sgrs, is_enabled=False)
        self._check_acl_log_drop(is_enabled=False)

    def test_events_all_sg(self):
        self._add_logs_then_remove(log_const.DROP_EVENT, log_const.ALL_EVENT)
        self._add_logs_then_remove(
            log_const.ACCEPT_EVENT, log_const.DROP_EVENT)
        self._add_logs_then_remove(
            log_const.DROP_EVENT, log_const.ACCEPT_EVENT)

    def test_events_one_sg(self):
        self._add_logs_then_remove(log_const.DROP_EVENT, log_const.ALL_EVENT,
                                   sg=self.sg1, sgrs=self.sg1rs)
        self._add_logs_then_remove(
            log_const.ACCEPT_EVENT, log_const.DROP_EVENT, sg=self.sg2,
            sgrs=self.sg2rs)
        self._add_logs_then_remove(
            log_const.DROP_EVENT, log_const.ACCEPT_EVENT, sg=self.sg3,
            sgrs=self.sg3rs)

    def test_disable_logs(self):
        # This test ensures that acls are correctly disabled when having
        # multiple log objects.

        # Check there are no acls with their logging active
        sgrs = self.sg1rs
        self._check_sgrs(sgrs, is_enabled=False)
        self._check_acl_log_drop(is_enabled=False)

        # Add accept log object
        log_data1 = self._log_data(sg_id=self.sg1)
        event1 = log_const.ACCEPT_EVENT
        log_data1['log']['event'] = event1
        log_obj1 = self.log_plugin.create_log(self.ctxt, log_data1)
        self._check_acl_log_drop(is_enabled=False)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        # Add drop log object
        log_data2 = self._log_data(sg_id=self.sg1)
        event2 = log_const.DROP_EVENT
        log_data2['log']['event'] = event2
        log_obj2 = self.log_plugin.create_log(self.ctxt, log_data2)
        self._check_acl_log_drop(is_enabled=True)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        # Disable drop log object and check it worked correctly
        log_data2['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj2['id'], log_data2)
        self._check_acl_log_drop(is_enabled=False)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        # Enable drop log and create all log object
        log_data2['log']['enabled'] = True
        self.log_plugin.update_log(self.ctxt, log_obj2['id'], log_data2)
        self._check_acl_log_drop(is_enabled=True)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)

        log_data3 = self._log_data(sg_id=self.sg1)
        log_data3['log']['event'] = log_const.ALL_EVENT
        log_obj3 = self.log_plugin.create_log(self.ctxt, log_data3)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)
        self._check_acl_log_drop(is_enabled=True)

        # Disable all log object and check all acls are still enabled (because
        # of the other objects)
        log_data3['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj3['id'], log_data3)
        self._check_sgrs(sgrs=sgrs, is_enabled=True)
        self._check_acl_log_drop(is_enabled=True)

        # Disable accept log object and only drop traffic gets logged
        log_data1['log']['enabled'] = False
        self.log_plugin.update_log(self.ctxt, log_obj1['id'], log_data1)
        self._check_sgrs(sgrs=sgrs, is_enabled=False)
        self._check_acl_log_drop(is_enabled=True)
