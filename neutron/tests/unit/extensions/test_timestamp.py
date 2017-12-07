# Copyright 2015 HuaWei Technologies.
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

import datetime

import mock
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_utils import timeutils
from oslo_utils import uuidutils
import six

from neutron.db import db_base_plugin_v2
from neutron.extensions import timestamp
from neutron import manager
from neutron.objects import network as net_obj
from neutron.objects import tag as tag_obj
from neutron.tests.unit.db import test_db_base_plugin_v2


class TimeStampExtensionManager(object):

    def get_resources(self):
        return []

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []

    def get_extended_resources(self, version):
        return timestamp.Timestamp().get_extended_resources(version)


class TimeStampTestPlugin(db_base_plugin_v2.NeutronDbPluginV2):
    """Just for test with TimeStampPlugin"""


class TimeStampChangedsinceTestCase(test_db_base_plugin_v2.
                                    NeutronDbPluginV2TestCase):
    plugin = ('neutron.tests.unit.extensions.test_timestamp.' +
              'TimeStampTestPlugin')

    def setUp(self):
        ext_mgr = TimeStampExtensionManager()
        super(TimeStampChangedsinceTestCase, self).setUp(plugin=self.plugin,
                                                         ext_mgr=ext_mgr)
        self.addCleanup(manager.NeutronManager.clear_instance)

    def setup_coreplugin(self, core_plugin=None, load_plugins=True):
        super(TimeStampChangedsinceTestCase, self).setup_coreplugin(
            self.plugin, load_plugins=False)
        self.patched_default_svc_plugins.return_value = ['timestamp']
        manager.init()

    def _get_resp_with_changed_since(self, resource_type, changed_since):
        query_params = 'changed_since=%s' % changed_since
        req = self.new_list_request('%ss' % resource_type, self.fmt,
                                    query_params)
        resources = self.deserialize(self.fmt, req.get_response(self.api))
        return resources

    def _return_by_timedelay(self, resource, timedelay):
        resource_type = six.next(six.iterkeys(resource))
        time_create = timeutils.parse_isotime(
            resource[resource_type]['updated_at'])
        time_before = datetime.timedelta(seconds=timedelay)
        addedtime_string = (datetime.datetime.
                            strftime(time_create + time_before,
                                     '%Y-%m-%dT%H:%M:%S')) + 'Z'
        return self._get_resp_with_changed_since(resource_type,
                                                 addedtime_string)

    def _update_test_resource_by_name(self, resource):
        resource_type = six.next(six.iterkeys(resource))
        name = resource[resource_type]['name']
        data = {resource_type: {'name': '%s_new' % name}}
        req = self.new_update_request('%ss' % resource_type,
                                      data,
                                      resource[resource_type]['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        return res

    def _set_timestamp_by_show(self, resource, type):
        req = self.new_show_request('%ss' % type,
                                    resource[type]['id'])
        res = self.deserialize(self.fmt, req.get_response(self.api))
        resource[type]['created_at'] = res[type]['created_at']
        resource[type]['updated_at'] = res[type]['updated_at']

    def _list_resources_with_changed_since(self, resource):
        # assert list results contain the net info when
        # changed_since equal with the net updated time.
        resource_type = six.next(six.iterkeys(resource))
        if resource_type in ['network', 'port']:
            self._set_timestamp_by_show(resource, resource_type)
        resources = self._get_resp_with_changed_since(resource_type,
                                                      resource[resource_type][
                                                          'updated_at'])
        self.assertEqual(resource[resource_type]['id'],
                         resources[resource_type + 's'][0]['id'])

        # assert list results contain the net info when changed_since
        # is earlier than the net updated time.
        resources = self._return_by_timedelay(resource, -1)
        self.assertEqual(resource[resource_type]['id'],
                         resources[resource_type + 's'][0]['id'])

        # assert list results is Null when changed_since
        # is later with the net updated time.
        resources = self._return_by_timedelay(resource, 1)
        self.assertEqual([], resources[resource_type + 's'])

    def _test_list_mutiple_resources_with_changed_since(self, first, second):
        resource_type = six.next(six.iterkeys(first))
        if resource_type in ['network', 'port']:
            self._set_timestamp_by_show(first, resource_type)
            self._set_timestamp_by_show(second, resource_type)
        # update names of second
        new_second = self._update_test_resource_by_name(second)
        # now the queue of order by
        # updated_at is first < new_second

        # test changed_since < first's updated_at
        resources = self._return_by_timedelay(first, -1)
        for resource in [first[resource_type]['id'],
                         new_second[resource_type]['id']]:
            self.assertIn(resource,
                          [n['id'] for n in resources[resource_type + 's']])

        # test changed_since = first's updated_at
        resources = self._return_by_timedelay(first, 0)
        for resource in [first[resource_type]['id'],
                         new_second[resource_type]['id']]:
            self.assertIn(resource,
                          [n['id'] for n in resources[resource_type + 's']])

        # test first < changed_since < second
        resources = self._return_by_timedelay(new_second, -1)
        self.assertIn(new_second[resource_type]['id'],
                      [n['id'] for n in resources[resource_type + 's']])

        # test first < changed_since = second
        resources = self._return_by_timedelay(new_second, 0)
        self.assertIn(new_second[resource_type]['id'],
                      [n['id'] for n in resources[resource_type + 's']])

        #test first < second < changed_since
        resources = self._return_by_timedelay(new_second, 3)
        self.assertEqual({resource_type + 's': []}, resources)

    def test_list_networks_with_changed_since(self):
        with self.network('net1') as net:
            self._list_resources_with_changed_since(net)

    def test_list_subnets_with_changed_since(self):
        with self.network('net2') as net:
            with self.subnet(network=net) as subnet:
                self._list_resources_with_changed_since(subnet)

    def test_list_ports_with_changed_since(self):
        with self.network('net3') as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet) as port:
                    self._list_resources_with_changed_since(port)

    def test_list_subnetpools_with_changed_since(self):
        prefixes = ['3.3.3.3/24', '4.4.4.4/24']
        with self.subnetpool(prefixes, tenant_id=self._tenant_id,
                             name='sp_test02') as subnetpool:
            self._list_resources_with_changed_since(subnetpool)

    def test_list_mutiple_networks_with_changed_since(self):
        with self.network('net1') as net1, self.network('net2') as net2:
            self._test_list_mutiple_resources_with_changed_since(net1, net2)

    def test_list_mutiple_subnets_with_changed_since(self):
        with self.network('net1') as net1, self.network('net2') as net2:
            with self.subnet(network=net1) as subnet1, self.subnet(
                    network=net2) as subnet2:
                self._test_list_mutiple_resources_with_changed_since(subnet1,
                                                                     subnet2)

    def test_list_mutiple_subnetpools_with_changed_since(self):
        prefixes1 = ['3.3.3.3/24', '4.4.4.4/24']
        prefixes2 = ['5.5.5.5/24', '6.6.6.6/24']
        with self.subnetpool(prefixes1,
                             tenant_id=self._tenant_id,
                             name='sp01') as sp1:
            with self.subnetpool(prefixes2,
                                 tenant_id=self._tenant_id,
                                 name='sp02') as sp2:
                self._test_list_mutiple_resources_with_changed_since(sp1, sp2)

    def test_list_mutiple_ports_with_changed_since(self):
        with self.network('net') as net:
            with self.subnet(network=net) as subnet:
                with self.port(subnet=subnet) as p1, self.port(
                        subnet=subnet) as p2:
                    self._test_list_mutiple_resources_with_changed_since(p1,
                                                                         p2)

    def test_list_resources_with_invalid_changed_since(self):
        # check when input --changed-since with no arg, then filters
        # stored as 'True'. And also check other invalid inputs
        changed_sinces = ['123', 'True', 'AAAA-BB-CCTDD-EE-FFZ',
                          '9a9b-11-00T99-1a-r3Z', '0000-00-00T00-00-00Z']
        for resource in ['network', 'subnet', 'port', 'subnetpool']:
            for changed_since in changed_sinces:
                req = self.new_list_request('%ss' % resource, self.fmt,
                                            'changed_since=%s' % changed_since)
                res = self.deserialize(self.fmt, req.get_response(self.api))
                self.assertEqual(list(res.values())[0]['type'], 'InvalidInput')

    def test_timestamp_fields_ignored_in_update(self):
        ctx = context.get_admin_context()
        with self.port() as port:
            plugin = directory.get_plugin()
            port = plugin.get_port(ctx, port['port']['id'])
            port['name'] = 'updated'
            port['created_at'] = '2011-04-06T14:34:23'
            port['updated_at'] = '2012-04-06T15:34:23'
            updated = plugin.update_port(ctx, port['id'], {'port': port})
        self.assertEqual('updated', updated['name'])
        self.assertNotEqual(port['updated_at'], updated['updated_at'])
        self.assertNotEqual(port['created_at'], updated['created_at'])


class TimeStampDBMixinTestCase(TimeStampChangedsinceTestCase):
    """Test timestamp_db.TimeStamp_db_mixin()"""

    def _save_network(self, network_id):
        ctx = context.get_admin_context()
        obj = net_obj.Network(ctx, id=network_id)
        obj.create()
        return obj.standard_attr_id

    # Use tag as non StandardAttribute object
    def _save_tag(self, tags, standard_attr_id):
        ctx = context.get_admin_context()
        for tag in tags:
            tag_obj.Tag(ctx, standard_attr_id=standard_attr_id,
                        tag=tag).create()

    def test_update_timpestamp(self):
        network_id = uuidutils.generate_uuid()
        tags = ["red", "blue"]
        with mock.patch('oslo_utils.timeutils.utcnow') as timenow:
            timenow.return_value = datetime.datetime(2016, 3, 11, 0, 0)

            # Test to update StandardAttribute object
            standard_attr_id = self._save_network(network_id)
            self.assertEqual(1, timenow.call_count)

            # Test not to update non StandardAttribute object
            self._save_tag(tags, standard_attr_id)
            self.assertEqual(1, timenow.call_count)
