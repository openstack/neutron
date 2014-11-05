# Copyright 2014 Big Switch Networks, Inc.  All rights reserved.
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
import contextlib
import os
import ssl

import mock
from oslo.config import cfg
import webob.exc

from neutron.openstack.common import log as logging
from neutron.tests.unit.bigswitch import fake_server
from neutron.tests.unit.bigswitch import test_base
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_db_plugin as test_plugin

LOG = logging.getLogger(__name__)

SERVERMANAGER = 'neutron.plugins.bigswitch.servermanager'
HTTPS = SERVERMANAGER + '.HTTPSConnectionWithValidation'
CERTCOMBINER = SERVERMANAGER + '.ServerPool._combine_certs_to_file'
FILEPUT = SERVERMANAGER + '.ServerPool._file_put_contents'
GETCACERTS = SERVERMANAGER + '.ServerPool._get_ca_cert_paths'
GETHOSTCERT = SERVERMANAGER + '.ServerPool._get_host_cert_path'
SSLGETCERT = SERVERMANAGER + '.ssl.get_server_certificate'
FAKECERTGET = 'neutron.tests.unit.bigswitch.fake_server.get_cert_contents'


class test_ssl_certificate_base(test_plugin.NeutronDbPluginV2TestCase,
                                test_base.BigSwitchTestBase):

    plugin_str = ('%s.NeutronRestProxyV2' %
                  test_base.RESTPROXY_PKG_PATH)
    servername = None
    cert_base = None

    def _setUp(self):
        self.servername = test_api_v2._uuid()
        self.cert_base = cfg.CONF.RESTPROXY.ssl_cert_directory
        self.host_cert_val = 'DUMMYCERTFORHOST%s' % self.servername
        self.host_cert_path = os.path.join(
            self.cert_base,
            'host_certs',
            '%s.pem' % self.servername
        )
        self.comb_cert_path = os.path.join(
            self.cert_base,
            'combined',
            '%s.pem' % self.servername
        )
        self.ca_certs_path = os.path.join(
            self.cert_base,
            'ca_certs'
        )
        cfg.CONF.set_override('servers', ["%s:443" % self.servername],
                              'RESTPROXY')
        self.setup_patches()

        # Mock method SSL lib uses to grab cert from server
        self.sslgetcert_m = mock.patch(SSLGETCERT, create=True).start()
        self.sslgetcert_m.return_value = self.host_cert_val

        # Mock methods that write and read certs from the file-system
        self.fileput_m = mock.patch(FILEPUT, create=True).start()
        self.certcomb_m = mock.patch(CERTCOMBINER, create=True).start()
        self.getcacerts_m = mock.patch(GETCACERTS, create=True).start()

        # this is used to configure what certificate contents the fake HTTPS
        # lib should expect to receive
        self.fake_certget_m = mock.patch(FAKECERTGET, create=True).start()

    def setUp(self):
        super(test_ssl_certificate_base, self).setUp(self.plugin_str)


class TestSslSticky(test_ssl_certificate_base):

    def setUp(self):
        self.setup_config_files()
        cfg.CONF.set_override('server_ssl', True, 'RESTPROXY')
        cfg.CONF.set_override('ssl_sticky', True, 'RESTPROXY')
        self._setUp()
        # Set fake HTTPS connection's expectation
        self.fake_certget_m.return_value = self.host_cert_val
        # No CA certs for this test
        self.getcacerts_m.return_value = []
        super(TestSslSticky, self).setUp()

    def test_sticky_cert(self):
        # SSL connection should be successful and cert should be cached
        with contextlib.nested(
            mock.patch(HTTPS, new=fake_server.HTTPSHostValidation),
            self.network()
        ):
            # CA certs should have been checked for
            self.getcacerts_m.assert_has_calls([mock.call(self.ca_certs_path)])
            # cert should have been fetched via SSL lib
            self.sslgetcert_m.assert_has_calls(
                [mock.call((self.servername, 443),
                           ssl_version=ssl.PROTOCOL_TLSv1)]
            )

            # cert should have been recorded
            self.fileput_m.assert_has_calls([mock.call(self.host_cert_path,
                                                       self.host_cert_val)])
            # no ca certs, so host cert only for this combined cert
            self.certcomb_m.assert_has_calls([mock.call([self.host_cert_path],
                                                        self.comb_cert_path)])


class TestSslHostCert(test_ssl_certificate_base):

    def setUp(self):
        self.setup_config_files()
        cfg.CONF.set_override('server_ssl', True, 'RESTPROXY')
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        self.httpsPatch = mock.patch(HTTPS, create=True,
                                     new=fake_server.HTTPSHostValidation)
        self.httpsPatch.start()
        self._setUp()
        # Set fake HTTPS connection's expectation
        self.fake_certget_m.return_value = self.host_cert_val
        # No CA certs for this test
        self.getcacerts_m.return_value = []
        # Pretend host cert exists
        self.hcertpath_p = mock.patch(GETHOSTCERT,
                                      return_value=(self.host_cert_path, True),
                                      create=True).start()
        super(TestSslHostCert, self).setUp()

    def test_host_cert(self):
        # SSL connection should be successful because of pre-configured cert
        with self.network():
            self.hcertpath_p.assert_has_calls([
                mock.call(os.path.join(self.cert_base, 'host_certs'),
                          self.servername)
            ])
            # sticky is disabled, no fetching allowed
            self.assertFalse(self.sslgetcert_m.call_count)
            # no ca certs, so host cert is only for this combined cert
            self.certcomb_m.assert_has_calls([mock.call([self.host_cert_path],
                                                        self.comb_cert_path)])


class TestSslCaCert(test_ssl_certificate_base):

    def setUp(self):
        self.setup_config_files()
        cfg.CONF.set_override('server_ssl', True, 'RESTPROXY')
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        self.httpsPatch = mock.patch(HTTPS, create=True,
                                     new=fake_server.HTTPSCAValidation)
        self.httpsPatch.start()
        self._setUp()

        # pretend to have a few ca certs
        self.getcacerts_m.return_value = ['ca1.pem', 'ca2.pem']

        # Set fake HTTPS connection's expectation
        self.fake_certget_m.return_value = 'DUMMYCERTIFICATEAUTHORITY'

        super(TestSslCaCert, self).setUp()

    def test_ca_cert(self):
        # SSL connection should be successful because CA cert was present
        # If not, attempting to create a network would raise an exception
        with self.network():
            # sticky is disabled, no fetching allowed
            self.assertFalse(self.sslgetcert_m.call_count)
            # 2 CAs and no host cert so combined should only contain both CAs
            self.certcomb_m.assert_has_calls([mock.call(['ca1.pem', 'ca2.pem'],
                                                        self.comb_cert_path)])


class TestSslWrongHostCert(test_ssl_certificate_base):

    def setUp(self):
        self.setup_config_files()
        cfg.CONF.set_override('server_ssl', True, 'RESTPROXY')
        cfg.CONF.set_override('ssl_sticky', True, 'RESTPROXY')
        self._setUp()

        # Set fake HTTPS connection's expectation to something wrong
        self.fake_certget_m.return_value = 'OTHERCERT'

        # No CA certs for this test
        self.getcacerts_m.return_value = []

        # Pretend host cert exists
        self.hcertpath_p = mock.patch(GETHOSTCERT,
                                      return_value=(self.host_cert_path, True),
                                      create=True).start()
        super(TestSslWrongHostCert, self).setUp()

    def test_error_no_cert(self):
        # since there will already be a host cert, sticky should not take
        # effect and there will be an error because the host cert's contents
        # will be incorrect
        tid = test_api_v2._uuid()
        data = {}
        data['network'] = {'tenant_id': tid, 'name': 'name',
                           'admin_state_up': True}
        with mock.patch(HTTPS, new=fake_server.HTTPSHostValidation):
            req = self.new_create_request('networks', data, 'json')
            res = req.get_response(self.api)
        self.assertEqual(res.status_int,
                         webob.exc.HTTPInternalServerError.code)
        self.hcertpath_p.assert_has_calls([
            mock.call(os.path.join(self.cert_base, 'host_certs'),
                      self.servername)
        ])
        # sticky is enabled, but a host cert already exists so it shant fetch
        self.assertFalse(self.sslgetcert_m.call_count)
        # no ca certs, so host cert only for this combined cert
        self.certcomb_m.assert_has_calls([mock.call([self.host_cert_path],
                                                    self.comb_cert_path)])


class TestSslNoValidation(test_ssl_certificate_base):

    def setUp(self):
        self.setup_config_files()
        cfg.CONF.set_override('server_ssl', True, 'RESTPROXY')
        cfg.CONF.set_override('ssl_sticky', False, 'RESTPROXY')
        cfg.CONF.set_override('no_ssl_validation', True, 'RESTPROXY')
        self._setUp()
        super(TestSslNoValidation, self).setUp()

    def test_validation_disabled(self):
        # SSL connection should be successful without any certificates
        # If not, attempting to create a network will raise an exception
        with contextlib.nested(
            mock.patch(HTTPS, new=fake_server.HTTPSNoValidation),
            self.network()
        ):
            # no sticky grabbing and no cert combining with no enforcement
            self.assertFalse(self.sslgetcert_m.call_count)
            self.assertFalse(self.certcomb_m.call_count)
