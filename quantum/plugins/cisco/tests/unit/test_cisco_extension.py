# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2011 OpenStack Foundation.
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
#
# @authors: Shweta Padubidri, Cisco Systems, Inc.
#           Peter Strunk , Cisco Systems, Inc.
#           Shubhangi Satras , Cisco Systems, Inc.

import logging
import os.path

import routes
import webob
from webtest import TestApp

from quantum.api import extensions
from quantum.api.extensions import (
    ExtensionMiddleware,
    PluginAwareExtensionManager,
)
from quantum.common import config
from quantum.extensions import (
    credential,
    qos,
)
from quantum.manager import QuantumManager
from quantum.openstack.common import jsonutils
from quantum.plugins.cisco.db import api as db
from quantum.plugins.cisco import l2network_plugin
from quantum.plugins.cisco.l2network_plugin import L2Network
from quantum.tests import base
from quantum.tests.unit.extension_stubs import StubBaseAppController
from quantum import wsgi


LOG = logging.getLogger('quantum.plugins.cisco.tests.test_cisco_extensions')


EXTENSIONS_PATH = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                               os.pardir, os.pardir, "extensions")

ROOTDIR = os.path.dirname(os.path.dirname(__file__))
UNITDIR = os.path.join(ROOTDIR, 'unit')


def testsdir(*p):
    return os.path.join(UNITDIR, *p)

config_file = 'quantum.conf.cisco.test'
args = ['--config-file', testsdir(config_file)]
config.parse(args=args)


class ExtensionsTestApp(wsgi.Router):

    def __init__(self, options=None):
        options = options or {}
        mapper = routes.Mapper()
        controller = StubBaseAppController()
        mapper.resource("dummy_resource", "/dummy_resources",
                        controller=controller)
        super(ExtensionsTestApp, self).__init__(mapper)

    def create_request(self, path, body, content_type, method='GET'):

        """ Test create request"""

        LOG.debug("test_create_request - START")
        req = webob.Request.blank(path)
        req.method = method
        req.headers = {}
        req.headers['Accept'] = content_type
        req.body = body
        LOG.debug("test_create_request - END")
        return req

    def _create_network(self, name=None):

        """ Test create network"""

        LOG.debug("Creating network - START")
        if name:
            net_name = name
        else:
            net_name = self.network_name
        net_path = "/tenants/tt/networks"
        net_data = {'network': {'name': '%s' % net_name}}
        req_body = wsgi.Serializer().serialize(net_data, self.contenttype)
        network_req = self.create_request(net_path, req_body,
                                          self.contenttype, 'POST')
        network_res = network_req.get_response(self.api)
        network_data = wsgi.Serializer().deserialize(network_res.body,
                                                     self.contenttype)
        LOG.debug("Creating network - END")
        return network_data['network']['id']

    def _create_port(self, network_id, port_state):

        """ Test create port"""

        LOG.debug("Creating port for network %s - START", network_id)
        port_path = "/tenants/tt/networks/%s/ports" % network_id
        port_req_data = {'port': {'state': '%s' % port_state}}
        req_body = wsgi.Serializer().serialize(port_req_data,
                                               self.contenttype)
        port_req = self.create_request(port_path, req_body,
                                       self.contenttype, 'POST')
        port_res = port_req.get_response(self.api)
        port_data = wsgi.Serializer().deserialize(port_res.body,
                                                  self.contenttype)
        LOG.debug("Creating port for network - END")
        return port_data['port']['id']

    def _delete_port(self, network_id, port_id):
        """ Delete port """
        LOG.debug("Deleting port for network %s - START", network_id)
        port_path = ("/tenants/tt/networks/%(network_id)s/ports/%(port_id)s" %
                     locals())
        port_req = self.create_request(port_path, None,
                                       self.contenttype, 'DELETE')
        port_req.get_response(self.api)
        LOG.debug("Deleting port for network - END")

    def _delete_network(self, network_id):
        """ Delete network """
        LOG.debug("Deleting network %s - START", network_id)
        network_path = "/tenants/tt/networks/%s" % network_id
        network_req = self.create_request(network_path, None,
                                          self.contenttype, 'DELETE')
        network_req.get_response(self.api)
        LOG.debug("Deleting network - END")

    def tear_down_port_network(self, net_id, port_id):
        """ Tear down port and network """

        self._delete_port(net_id, port_id)
        self._delete_network(net_id)


class QosExtensionTest(base.BaseTestCase):

    def setUp(self):

        """ Set up function """

        super(QosExtensionTest, self).setUp()
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/csco/tenants")
        controller = qos.QosController(QuantumManager.get_plugin())
        res_ext = extensions.ResourceExtension('qos', controller,
                                               parent=parent_resource)

        self.test_app = setup_extensions_test_app(
            SimpleExtensionManager(res_ext))
        self.contenttype = 'application/json'
        self.qos_path = '/extensions/csco/tenants/tt/qos'
        self.qos_second_path = '/extensions/csco/tenants/tt/qos/'
        self.test_qos_data = {
            'qos': {
                'qos_name': 'cisco_test_qos',
                'qos_desc': {
                    'PPS': 50,
                    'TTL': 5,
                },
            },
        }
        self._l2network_plugin = l2network_plugin.L2Network()

    def test_create_qos(self):

        """ Test create qos """

        LOG.debug("test_create_qos - START")
        req_body = jsonutils.dumps(self.test_qos_data)
        index_response = self.test_app.post(self.qos_path,
                                            req_body,
                                            content_type=self.contenttype)
        self.assertEqual(200, index_response.status_int)

        # Clean Up - Delete the qos
        resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                  self.contenttype)
        qos_path_temp = self.qos_second_path + resp_body['qoss']['qos']['id']
        qos_path = str(qos_path_temp)
        self.tearDownQos(qos_path)
        LOG.debug("test_create_qos - END")

    def test_create_qosBADRequest(self):

        """ Test create qos bad request """

        LOG.debug("test_create_qosBADRequest - START")
        index_response = self.test_app.post(self.qos_path,
                                            'BAD_REQUEST',
                                            content_type=self.contenttype,
                                            status='*')
        self.assertEqual(400, index_response.status_int)
        LOG.debug("test_create_qosBADRequest - END")

    def test_list_qoss(self):

        """ Test list qoss """

        LOG.debug("test_list_qoss - START")
        req_body1 = jsonutils.dumps(self.test_qos_data)
        create_resp1 = self.test_app.post(self.qos_path, req_body1,
                                          content_type=self.contenttype)
        req_body2 = jsonutils.dumps({
            'qos': {
                'qos_name': 'cisco_test_qos2',
                'qos_desc': {
                    'PPS': 50,
                    'TTL': 5,
                },
            },
        })
        create_resp2 = self.test_app.post(self.qos_path, req_body2,
                                          content_type=self.contenttype)
        index_response = self.test_app.get(self.qos_path)
        index_resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                        self.contenttype)
        self.assertEqual(200, index_response.status_int)

        # Clean Up - Delete the qos's
        resp_body1 = wsgi.Serializer().deserialize(create_resp1.body,
                                                   self.contenttype)
        qos_path1_temp = self.qos_second_path + resp_body1['qoss']['qos']['id']
        qos_path1 = str(qos_path1_temp)
        resp_body2 = wsgi.Serializer().deserialize(create_resp2.body,
                                                   self.contenttype)
        list_all_qos = [resp_body1['qoss']['qos'], resp_body2['qoss']['qos']]
        self.assertTrue(index_resp_body['qoss'][0] in list_all_qos)
        self.assertTrue(index_resp_body['qoss'][1] in list_all_qos)
        qos_path2_temp = self.qos_second_path + resp_body2['qoss']['qos']['id']
        qos_path2 = str(qos_path2_temp)
        self.tearDownQos(qos_path1)
        self.tearDownQos(qos_path2)
        LOG.debug("test_list_qoss - END")

    def test_show_qos(self):

        """ Test show qos """

        LOG.debug("test_show_qos - START")
        req_body = jsonutils.dumps(self.test_qos_data)
        index_response = self.test_app.post(self.qos_path, req_body,
                                            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                  self.contenttype)
        show_path_temp = self.qos_second_path + resp_body['qoss']['qos']['id']
        show_qos_path = str(show_path_temp)
        show_response = self.test_app.get(show_qos_path)
        show_resp_dict = wsgi.Serializer().deserialize(show_response.body,
                                                       self.contenttype)
        self.assertEqual(show_resp_dict['qoss']['qos']['name'],
                         self.test_qos_data['qos']['qos_name'])

        self.assertEqual(200, show_response.status_int)

        # Clean Up - Delete the qos
        self.tearDownQos(show_qos_path)
        LOG.debug("test_show_qos - END")

    def test_show_qosDNE(self, qos_id='100'):

        """ Test show qos does not exist"""

        LOG.debug("test_show_qosDNE - START")
        show_path_temp = self.qos_second_path + qos_id
        show_qos_path = str(show_path_temp)
        show_response = self.test_app.get(show_qos_path, status='*')
        self.assertEqual(452, show_response.status_int)
        LOG.debug("test_show_qosDNE - END")

    def test_update_qos(self):

        """ Test update qos """

        LOG.debug("test_update_qos - START")
        req_body = jsonutils.dumps(self.test_qos_data)
        index_response = self.test_app.post(self.qos_path, req_body,
                                            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                  self.contenttype)
        rename_req_body = jsonutils.dumps({
            'qos': {
                'qos_name': 'cisco_rename_qos',
                'qos_desc': {
                    'PPS': 50,
                    'TTL': 5,
                },
            },
        })
        rename_path_temp = (self.qos_second_path +
                            resp_body['qoss']['qos']['id'])
        rename_path = str(rename_path_temp)
        rename_response = self.test_app.put(rename_path, rename_req_body,
                                            content_type=self.contenttype)
        self.assertEqual(200, rename_response.status_int)
        rename_resp_dict = wsgi.Serializer().deserialize(rename_response.body,
                                                         self.contenttype)
        self.assertEqual(rename_resp_dict['qoss']['qos']['name'],
                         'cisco_rename_qos')
        self.tearDownQos(rename_path)
        LOG.debug("test_update_qos - END")

    def test_update_qosDNE(self, qos_id='100'):

        """ Test update qos does not exist """

        LOG.debug("test_update_qosDNE - START")
        rename_req_body = jsonutils.dumps({
            'qos': {
                'qos_name': 'cisco_rename_qos',
                'qos_desc': {
                    'PPS': 50,
                    'TTL': 5,
                },
            },
        })
        rename_path_temp = self.qos_second_path + qos_id
        rename_path = str(rename_path_temp)
        rename_response = self.test_app.put(rename_path, rename_req_body,
                                            content_type=self.contenttype,
                                            status='*')
        self.assertEqual(452, rename_response.status_int)
        LOG.debug("test_update_qosDNE - END")

    def test_update_qosBADRequest(self):

        """ Test update qos bad request """

        LOG.debug("test_update_qosBADRequest - START")
        req_body = jsonutils.dumps(self.test_qos_data)
        index_response = self.test_app.post(self.qos_path, req_body,
                                            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                  self.contenttype)
        rename_path_temp = (self.qos_second_path +
                            resp_body['qoss']['qos']['id'])
        rename_path = str(rename_path_temp)
        rename_response = self.test_app.put(rename_path, 'BAD_REQUEST',
                                            status="*")
        self.assertEqual(400, rename_response.status_int)

        # Clean Up - Delete the Port Profile
        self.tearDownQos(rename_path)
        LOG.debug("test_update_qosBADRequest - END")

    def test_delete_qos(self):

        """ Test delte qos """

        LOG.debug("test_delete_qos - START")
        req_body = jsonutils.dumps({
            'qos': {
                'qos_name': 'cisco_test_qos',
                'qos_desc': {
                    'PPS': 50,
                    'TTL': 5,
                },
            },
        })
        index_response = self.test_app.post(self.qos_path, req_body,
                                            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                  self.contenttype)
        delete_path_temp = (self.qos_second_path +
                            resp_body['qoss']['qos']['id'])
        delete_path = str(delete_path_temp)
        delete_response = self.test_app.delete(delete_path)
        self.assertEqual(200, delete_response.status_int)
        LOG.debug("test_delete_qos - END")

    def test_delete_qosDNE(self, qos_id='100'):

        """ Test delte qos does not exist"""

        LOG.debug("test_delete_qosDNE - START")
        delete_path_temp = self.qos_second_path + qos_id
        delete_path = str(delete_path_temp)
        delete_response = self.test_app.delete(delete_path, status='*')
        self.assertEqual(452, delete_response.status_int)
        LOG.debug("test_delete_qosDNE - END")

    def tearDownQos(self, delete_profile_path):

        """ Tear Down Qos """

        self.test_app.delete(delete_profile_path)

    def tearDown(self):
        db.clear_db()


class CredentialExtensionTest(base.BaseTestCase):

    def setUp(self):

        """ Set up function """

        super(CredentialExtensionTest, self).setUp()
        parent_resource = dict(member_name="tenant",
                               collection_name="extensions/csco/tenants")
        controller = credential.CredentialController(QuantumManager.
                                                     get_plugin())
        res_ext = extensions.ResourceExtension('credentials', controller,
                                               parent=parent_resource)
        self.test_app = setup_extensions_test_app(SimpleExtensionManager(
                                                  res_ext))
        self.contenttype = 'application/json'
        self.credential_path = '/extensions/csco/tenants/tt/credentials'
        self.cred_second_path = '/extensions/csco/tenants/tt/credentials/'
        self.test_credential_data = {
            'credential': {
                'credential_name': 'cred8',
                'user_name': 'newUser2',
                'password': 'newPasswd1',
            },
        }
        self._l2network_plugin = l2network_plugin.L2Network()

    def test_list_credentials(self):

        """ Test list credentials """

        #Create Credential before listing
        LOG.debug("test_list_credentials - START")
        req_body1 = jsonutils.dumps(self.test_credential_data)
        create_response1 = self.test_app.post(
            self.credential_path, req_body1,
            content_type=self.contenttype)
        req_body2 = jsonutils.dumps({
            'credential': {
                'credential_name': 'cred9',
                'user_name': 'newUser2',
                'password': 'newPasswd2',
            },
        })
        create_response2 = self.test_app.post(
            self.credential_path, req_body2,
            content_type=self.contenttype)
        index_response = self.test_app.get(self.credential_path)
        index_resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                        self.contenttype)
        self.assertEqual(200, index_response.status_int)
        #CLean Up - Deletion of the Credentials
        resp_body1 = wsgi.Serializer().deserialize(create_response1.body,
                                                   self.contenttype)
        delete_path1_temp = (self.cred_second_path +
                             resp_body1['credentials']['credential']['id'])
        delete_path1 = str(delete_path1_temp)
        resp_body2 = wsgi.Serializer().deserialize(create_response2.body,
                                                   self.contenttype)
        list_all_credential = [resp_body1['credentials']['credential'],
                               resp_body2['credentials']['credential']]
        self.assertTrue(
            index_resp_body['credentials'][0] in list_all_credential)
        self.assertTrue(
            index_resp_body['credentials'][1] in list_all_credential)
        delete_path2_temp = (self.cred_second_path +
                             resp_body2['credentials']['credential']['id'])
        delete_path2 = str(delete_path2_temp)
        self.tearDownCredential(delete_path1)
        self.tearDownCredential(delete_path2)
        LOG.debug("test_list_credentials - END")

    def test_create_credential(self):

        """ Test create credential """

        LOG.debug("test_create_credential - START")
        req_body = jsonutils.dumps(self.test_credential_data)
        index_response = self.test_app.post(
            self.credential_path, req_body,
            content_type=self.contenttype)
        self.assertEqual(200, index_response.status_int)
        #CLean Up - Deletion of the Credentials
        resp_body = wsgi.Serializer().deserialize(
            index_response.body, self.contenttype)
        delete_path_temp = (self.cred_second_path +
                            resp_body['credentials']['credential']['id'])
        delete_path = str(delete_path_temp)
        self.tearDownCredential(delete_path)
        LOG.debug("test_create_credential - END")

    def test_create_credentialBADRequest(self):

        """ Test create credential bad request """

        LOG.debug("test_create_credentialBADRequest - START")
        index_response = self.test_app.post(
            self.credential_path, 'BAD_REQUEST',
            content_type=self.contenttype, status='*')
        self.assertEqual(400, index_response.status_int)
        LOG.debug("test_create_credentialBADRequest - END")

    def test_show_credential(self):

        """ Test show credential """

        LOG.debug("test_show_credential - START")
        req_body = jsonutils.dumps(self.test_credential_data)
        index_response = self.test_app.post(
            self.credential_path, req_body,
            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(index_response.body,
                                                  self.contenttype)
        show_path_temp = (self.cred_second_path +
                          resp_body['credentials']['credential']['id'])
        show_cred_path = str(show_path_temp)
        show_response = self.test_app.get(show_cred_path)
        show_resp_dict = wsgi.Serializer().deserialize(show_response.body,
                                                       self.contenttype)
        self.assertEqual(show_resp_dict['credentials']['credential']['name'],
                         self.test_credential_data['credential']['user_name'])
        self.assertEqual(
            show_resp_dict['credentials']['credential']['password'],
            self.test_credential_data['credential']['password'])
        self.assertEqual(200, show_response.status_int)
        LOG.debug("test_show_credential - END")

    def test_show_credentialDNE(self, credential_id='100'):

        """ Test show credential does not exist """

        LOG.debug("test_show_credentialDNE - START")
        show_path_temp = self.cred_second_path + credential_id
        show_cred_path = str(show_path_temp)
        show_response = self.test_app.get(show_cred_path, status='*')
        self.assertEqual(451, show_response.status_int)
        LOG.debug("test_show_credentialDNE - END")

    def test_update_credential(self):

        """ Test update credential """

        LOG.debug("test_update_credential - START")
        req_body = jsonutils.dumps(self.test_credential_data)

        index_response = self.test_app.post(
            self.credential_path, req_body,
            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(
            index_response.body, self.contenttype)
        rename_req_body = jsonutils.dumps({
            'credential': {
                'credential_name': 'cred3',
                'user_name': 'RenamedUser',
                'password': 'Renamedpassword',
            },
        })
        rename_path_temp = (self.cred_second_path +
                            resp_body['credentials']['credential']['id'])
        rename_path = str(rename_path_temp)
        rename_response = self.test_app.put(rename_path, rename_req_body,
                                            content_type=self.contenttype)
        rename_resp_dict = wsgi.Serializer().deserialize(rename_response.body,
                                                         self.contenttype)
        self.assertEqual(rename_resp_dict['credentials']['credential']['name'],
                         'cred3')
        self.assertEqual(
            rename_resp_dict['credentials']['credential']['password'],
            self.test_credential_data['credential']['password'])
        self.assertEqual(200, rename_response.status_int)
        # Clean Up - Delete the Credentials
        self.tearDownCredential(rename_path)
        LOG.debug("test_update_credential - END")

    def test_update_credBADReq(self):

        """ Test update credential bad request """

        LOG.debug("test_update_credBADReq - START")
        req_body = jsonutils.dumps(self.test_credential_data)
        index_response = self.test_app.post(
            self.credential_path, req_body,
            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(
            index_response.body, self.contenttype)
        rename_path_temp = (self.cred_second_path +
                            resp_body['credentials']['credential']['id'])
        rename_path = str(rename_path_temp)
        rename_response = self.test_app.put(rename_path, 'BAD_REQUEST',
                                            status='*')
        self.assertEqual(400, rename_response.status_int)
        LOG.debug("test_update_credBADReq - END")

    def test_update_credentialDNE(self, credential_id='100'):

        """ Test update credential does not exist"""

        LOG.debug("test_update_credentialDNE - START")
        rename_req_body = jsonutils.dumps({
            'credential': {
                'credential_name': 'cred3',
                'user_name': 'RenamedUser',
                'password': 'Renamedpassword',
            },
        })
        rename_path_temp = self.cred_second_path + credential_id
        rename_path = str(rename_path_temp)
        rename_response = self.test_app.put(rename_path, rename_req_body,
                                            content_type=self.contenttype,
                                            status='*')
        self.assertEqual(451, rename_response.status_int)
        LOG.debug("test_update_credentialDNE - END")

    def test_delete_credential(self):

        """ Test delete credential """

        LOG.debug("test_delete_credential - START")
        req_body = jsonutils.dumps(self.test_credential_data)
        index_response = self.test_app.post(
            self.credential_path, req_body,
            content_type=self.contenttype)
        resp_body = wsgi.Serializer().deserialize(
            index_response.body, self.contenttype)
        delete_path_temp = (self.cred_second_path +
                            resp_body['credentials']['credential']['id'])
        delete_path = str(delete_path_temp)
        delete_response = self.test_app.delete(delete_path)
        self.assertEqual(200, delete_response.status_int)
        LOG.debug("test_delete_credential - END")

    def test_delete_credentialDNE(self, credential_id='100'):

        """ Test delete credential does not exist """

        LOG.debug("test_delete_credentialDNE - START")
        delete_path_temp = self.cred_second_path + credential_id
        delete_path = str(delete_path_temp)
        delete_response = self.test_app.delete(delete_path, status='*')
        self.assertEqual(451, delete_response.status_int)
        LOG.debug("test_delete_credentialDNE - END")

    def tearDownCredential(self, delete_path):
        self.test_app.delete(delete_path)

    def tearDown(self):
        db.clear_db()


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return ExtensionsTestApp(conf)


def setup_extensions_middleware(extension_manager=None):
    extension_manager = (extension_manager or
                         PluginAwareExtensionManager(EXTENSIONS_PATH,
                                                     L2Network()))
    app = config.load_paste_app('extensions_test_app')
    return ExtensionMiddleware(app, ext_mgr=extension_manager)


def setup_extensions_test_app(extension_manager=None):
    return TestApp(setup_extensions_middleware(extension_manager))


class SimpleExtensionManager(object):

    def __init__(self, resource_ext=None, action_ext=None, request_ext=None):
        self.resource_ext = resource_ext
        self.action_ext = action_ext
        self.request_ext = request_ext

    def get_resources(self):
        resource_exts = []
        if self.resource_ext:
            resource_exts.append(self.resource_ext)
        return resource_exts

    def get_actions(self):
        action_exts = []
        if self.action_ext:
            action_exts.append(self.action_ext)
        return action_exts

    def get_request_extensions(self):
        request_extensions = []
        if self.request_ext:
            request_extensions.append(self.request_ext)
        return request_extensions
