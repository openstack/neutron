# Copyright 2013 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import mock

from neutron.common import exceptions
from neutron.plugins.vmware.api_client import exception as api_exc
from neutron.plugins.vmware.common import exceptions as nsx_exc
from neutron.plugins.vmware.common import utils
from neutron.plugins.vmware.nsxlib import lsn as lsnlib
from neutron.tests import base


class LSNTestCase(base.BaseTestCase):

    def setUp(self):
        super(LSNTestCase, self).setUp()
        self.mock_request_p = mock.patch.object(lsnlib, 'do_request')
        self.mock_request = self.mock_request_p.start()
        self.cluster = mock.Mock()
        self.cluster.default_service_cluster_uuid = 'foo'
        self.addCleanup(self.mock_request_p.stop)

    def test_service_cluster_None(self):
        self.mock_request.return_value = None
        expected = lsnlib.service_cluster_exists(None, None)
        self.assertFalse(expected)

    def test_service_cluster_found(self):
        self.mock_request.return_value = {
            "results": [
                {
                    "_href": "/ws.v1/service-cluster/foo_uuid",
                    "display_name": "foo_name",
                    "uuid": "foo_uuid",
                    "tags": [],
                    "_schema": "/ws.v1/schema/ServiceClusterConfig",
                    "gateways": []
                }
            ],
            "result_count": 1
        }
        expected = lsnlib.service_cluster_exists(None, 'foo_uuid')
        self.assertTrue(expected)

    def test_service_cluster_not_found(self):
        self.mock_request.side_effect = exceptions.NotFound()
        expected = lsnlib.service_cluster_exists(None, 'foo_uuid')
        self.assertFalse(expected)

    def test_lsn_for_network_create(self):
        net_id = "foo_network_id"
        tags = utils.get_tags(n_network_id=net_id)
        obj = {"edge_cluster_uuid": "foo", "tags": tags}
        lsnlib.lsn_for_network_create(self.cluster, net_id)
        self.mock_request.assert_called_once_with(
            "POST", "/ws.v1/lservices-node",
            json.dumps(obj), cluster=self.cluster)

    def test_lsn_for_network_get(self):
        net_id = "foo_network_id"
        lsn_id = "foo_lsn_id"
        self.mock_request.return_value = {
            "results": [{"uuid": "foo_lsn_id"}],
            "result_count": 1
        }
        result = lsnlib.lsn_for_network_get(self.cluster, net_id)
        self.assertEqual(lsn_id, result)
        self.mock_request.assert_called_once_with(
            "GET",
            ("/ws.v1/lservices-node?fields=uuid&tag_scope="
             "n_network_id&tag=%s" % net_id),
            cluster=self.cluster)

    def test_lsn_for_network_get_none(self):
        net_id = "foo_network_id"
        self.mock_request.return_value = {
            "results": [{"uuid": "foo_lsn_id1"}, {"uuid": "foo_lsn_id2"}],
            "result_count": 2
        }
        result = lsnlib.lsn_for_network_get(self.cluster, net_id)
        self.assertIsNone(result)

    def test_lsn_for_network_get_raise_not_found(self):
        net_id = "foo_network_id"
        self.mock_request.return_value = {
            "results": [], "result_count": 0
        }
        self.assertRaises(exceptions.NotFound,
                          lsnlib.lsn_for_network_get,
                          self.cluster, net_id)

    def test_lsn_delete(self):
        lsn_id = "foo_id"
        lsnlib.lsn_delete(self.cluster, lsn_id)
        self.mock_request.assert_called_once_with(
            "DELETE",
            "/ws.v1/lservices-node/%s" % lsn_id, cluster=self.cluster)

    def _test_lsn_port_host_entries_update(self, lsn_type, hosts_data):
        lsn_id = 'foo_lsn_id'
        lsn_port_id = 'foo_lsn_port_id'
        lsnlib.lsn_port_host_entries_update(
            self.cluster, lsn_id, lsn_port_id, lsn_type, hosts_data)
        self.mock_request.assert_called_once_with(
            'PUT',
            '/ws.v1/lservices-node/%s/lport/%s/%s' % (lsn_id,
                                                      lsn_port_id,
                                                      lsn_type),
            json.dumps({'hosts': hosts_data}),
            cluster=self.cluster)

    def test_lsn_port_dhcp_entries_update(self):
        hosts_data = [{"ip_address": "11.22.33.44",
                       "mac_address": "aa:bb:cc:dd:ee:ff"},
                      {"ip_address": "44.33.22.11",
                       "mac_address": "ff:ee:dd:cc:bb:aa"}]
        self._test_lsn_port_host_entries_update("dhcp", hosts_data)

    def test_lsn_port_metadata_entries_update(self):
        hosts_data = [{"ip_address": "11.22.33.44",
                       "device_id": "foo_vm_uuid"}]
        self._test_lsn_port_host_entries_update("metadata-proxy", hosts_data)

    def test_lsn_port_create(self):
        port_data = {
            "ip_address": "1.2.3.0/24",
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "subnet_id": "foo_subnet_id"
        }
        port_id = "foo_port_id"
        self.mock_request.return_value = {"uuid": port_id}
        lsn_id = "foo_lsn_id"
        result = lsnlib.lsn_port_create(self.cluster, lsn_id, port_data)
        self.assertEqual(result, port_id)
        tags = utils.get_tags(n_subnet_id=port_data["subnet_id"],
                              n_mac_address=port_data["mac_address"])
        port_obj = {
            "ip_address": port_data["ip_address"],
            "mac_address": port_data["mac_address"],
            "type": "LogicalServicesNodePortConfig",
            "tags": tags
        }
        self.mock_request.assert_called_once_with(
            "POST", "/ws.v1/lservices-node/%s/lport" % lsn_id,
            json.dumps(port_obj), cluster=self.cluster)

    def test_lsn_port_delete(self):
        lsn_id = "foo_lsn_id"
        lsn_port_id = "foo_port_id"
        lsnlib.lsn_port_delete(self.cluster, lsn_id, lsn_port_id)
        self.mock_request.assert_called_once_with(
            "DELETE",
            "/ws.v1/lservices-node/%s/lport/%s" % (lsn_id, lsn_port_id),
            cluster=self.cluster)

    def test_lsn_port_get_with_filters(self):
        lsn_id = "foo_lsn_id"
        port_id = "foo_port_id"
        filters = {"tag": "foo_tag", "tag_scope": "foo_scope"}
        self.mock_request.return_value = {
            "results": [{"uuid": port_id}],
            "result_count": 1
        }
        result = lsnlib._lsn_port_get(self.cluster, lsn_id, filters)
        self.assertEqual(result, port_id)
        self.mock_request.assert_called_once_with(
            "GET",
            ("/ws.v1/lservices-node/%s/lport?fields=uuid&tag_scope=%s&"
             "tag=%s" % (lsn_id, filters["tag_scope"], filters["tag"])),
            cluster=self.cluster)

    def test_lsn_port_get_with_filters_return_none(self):
        self.mock_request.return_value = {
            "results": [{"uuid": "foo1"}, {"uuid": "foo2"}],
            "result_count": 2
        }
        result = lsnlib._lsn_port_get(self.cluster, "lsn_id", None)
        self.assertIsNone(result)

    def test_lsn_port_get_with_filters_raises_not_found(self):
        self.mock_request.return_value = {"results": [], "result_count": 0}
        self.assertRaises(exceptions.NotFound,
                          lsnlib._lsn_port_get,
                          self.cluster, "lsn_id", None)

    def test_lsn_port_info_get(self):
        self.mock_request.return_value = {
            "tags": [
                {"scope": "n_mac_address", "tag": "fa:16:3e:27:fd:a0"},
                {"scope": "n_subnet_id", "tag": "foo_subnet_id"},
            ],
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "0.0.0.0/0",
            "uuid": "foo_lsn_port_id"
        }
        result = lsnlib.lsn_port_info_get(
            self.cluster, 'foo_lsn_id', 'foo_lsn_port_id')
        self.mock_request.assert_called_once_with(
            'GET', '/ws.v1/lservices-node/foo_lsn_id/lport/foo_lsn_port_id',
            cluster=self.cluster)
        self.assertIn('subnet_id', result)
        self.assertIn('mac_address', result)

    def test_lsn_port_info_get_raise_not_found(self):
        self.mock_request.side_effect = exceptions.NotFound
        self.assertRaises(exceptions.NotFound,
                          lsnlib.lsn_port_info_get,
                          self.cluster, mock.ANY, mock.ANY)

    def test_lsn_port_plug_network(self):
        lsn_id = "foo_lsn_id"
        lsn_port_id = "foo_lsn_port_id"
        lswitch_port_id = "foo_lswitch_port_id"
        lsnlib.lsn_port_plug_network(
            self.cluster, lsn_id, lsn_port_id, lswitch_port_id)
        self.mock_request.assert_called_once_with(
            "PUT",
            ("/ws.v1/lservices-node/%s/lport/%s/"
             "attachment") % (lsn_id, lsn_port_id),
            json.dumps({"peer_port_uuid": lswitch_port_id,
                        "type": "PatchAttachment"}),
            cluster=self.cluster)

    def test_lsn_port_plug_network_raise_conflict(self):
        lsn_id = "foo_lsn_id"
        lsn_port_id = "foo_lsn_port_id"
        lswitch_port_id = "foo_lswitch_port_id"
        self.mock_request.side_effect = api_exc.Conflict
        self.assertRaises(
            nsx_exc.LsnConfigurationConflict,
            lsnlib.lsn_port_plug_network,
            self.cluster, lsn_id, lsn_port_id, lswitch_port_id)

    def _test_lsn_port_dhcp_configure(
        self, lsn_id, lsn_port_id, is_enabled, opts):
        lsnlib.lsn_port_dhcp_configure(
            self.cluster, lsn_id, lsn_port_id, is_enabled, opts)
        opt_array = [
            {"name": key, "value": val}
            for key, val in opts.iteritems()
        ]
        self.mock_request.assert_has_calls([
            mock.call("PUT", "/ws.v1/lservices-node/%s/dhcp" % lsn_id,
                      json.dumps({"enabled": is_enabled}),
                      cluster=self.cluster),
            mock.call("PUT",
                      ("/ws.v1/lservices-node/%s/"
                       "lport/%s/dhcp") % (lsn_id, lsn_port_id),
                      json.dumps({"options": opt_array}),
                      cluster=self.cluster)
        ])

    def test_lsn_port_dhcp_configure_empty_opts(self):
        lsn_id = "foo_lsn_id"
        lsn_port_id = "foo_lsn_port_id"
        is_enabled = False
        opts = {}
        self._test_lsn_port_dhcp_configure(
            lsn_id, lsn_port_id, is_enabled, opts)

    def test_lsn_port_dhcp_configure_with_opts(self):
        lsn_id = "foo_lsn_id"
        lsn_port_id = "foo_lsn_port_id"
        is_enabled = True
        opts = {"opt1": "val1", "opt2": "val2"}
        self._test_lsn_port_dhcp_configure(
            lsn_id, lsn_port_id, is_enabled, opts)

    def _test_lsn_metadata_configure(
        self, lsn_id, is_enabled, opts, expected_opts):
        lsnlib.lsn_metadata_configure(
            self.cluster, lsn_id, is_enabled, opts)
        lsn_obj = {"enabled": is_enabled}
        lsn_obj.update(expected_opts)
        self.mock_request.assert_has_calls([
            mock.call("PUT",
                      "/ws.v1/lservices-node/%s/metadata-proxy" % lsn_id,
                      json.dumps(lsn_obj),
                      cluster=self.cluster),
        ])

    def test_lsn_port_metadata_configure_empty_secret(self):
        lsn_id = "foo_lsn_id"
        is_enabled = True
        opts = {
            "metadata_server_ip": "1.2.3.4",
            "metadata_server_port": "8775"
        }
        expected_opts = {
            "metadata_server_ip": "1.2.3.4",
            "metadata_server_port": "8775",
        }
        self._test_lsn_metadata_configure(
            lsn_id, is_enabled, opts, expected_opts)

    def test_lsn_metadata_configure_with_secret(self):
        lsn_id = "foo_lsn_id"
        is_enabled = True
        opts = {
            "metadata_server_ip": "1.2.3.4",
            "metadata_server_port": "8775",
            "metadata_proxy_shared_secret": "foo_secret"
        }
        expected_opts = {
            "metadata_server_ip": "1.2.3.4",
            "metadata_server_port": "8775",
            "options": [{
                "name": "metadata_proxy_shared_secret",
                "value": "foo_secret"
            }]
        }
        self._test_lsn_metadata_configure(
            lsn_id, is_enabled, opts, expected_opts)

    def _test_lsn_port_host_action(
            self, lsn_port_action_func, extra_action, action, host):
        lsn_id = "foo_lsn_id"
        lsn_port_id = "foo_lsn_port_id"
        lsn_port_action_func(self.cluster, lsn_id, lsn_port_id, host)
        self.mock_request.assert_called_once_with(
            "POST",
            ("/ws.v1/lservices-node/%s/lport/"
             "%s/%s?action=%s") % (lsn_id, lsn_port_id, extra_action, action),
            json.dumps(host), cluster=self.cluster)

    def test_lsn_port_dhcp_host_add(self):
        host = {
            "ip_address": "1.2.3.4",
            "mac_address": "aa:bb:cc:dd:ee:ff"
        }
        self._test_lsn_port_host_action(
            lsnlib.lsn_port_dhcp_host_add, "dhcp", "add_host", host)

    def test_lsn_port_dhcp_host_remove(self):
        host = {
            "ip_address": "1.2.3.4",
            "mac_address": "aa:bb:cc:dd:ee:ff"
        }
        self._test_lsn_port_host_action(
            lsnlib.lsn_port_dhcp_host_remove, "dhcp", "remove_host", host)

    def test_lsn_port_metadata_host_add(self):
        host = {
            "ip_address": "1.2.3.4",
            "instance_id": "foo_instance_id"
        }
        self._test_lsn_port_host_action(lsnlib.lsn_port_metadata_host_add,
                                        "metadata-proxy", "add_host", host)

    def test_lsn_port_metadata_host_remove(self):
        host = {
            "ip_address": "1.2.3.4",
            "instance_id": "foo_instance_id"
        }
        self._test_lsn_port_host_action(lsnlib.lsn_port_metadata_host_remove,
                                        "metadata-proxy", "remove_host", host)
