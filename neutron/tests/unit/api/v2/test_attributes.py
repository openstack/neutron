# Copyright 2012 OpenStack Foundation
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

from neutron_lib.api import converters
from neutron_lib import constants
from neutron_lib import exceptions as n_exc
from oslo_utils import uuidutils
import webob.exc

from neutron.api.v2 import attributes
from neutron import context
from neutron.tests import base


class TestResDict(base.BaseTestCase):
    class _MyException(Exception):
        pass
    _EXC_CLS = _MyException

    def _test_fill_default_value(self, attr_info, expected, res_dict):
        attributes.fill_default_value(attr_info, res_dict)
        self.assertEqual(expected, res_dict)

    def test_fill_default_value(self):
        attr_info = {
            'key': {
                'allow_post': True,
                'default': constants.ATTR_NOT_SPECIFIED,
            },
        }
        self._test_fill_default_value(attr_info, {'key': 'X'}, {'key': 'X'})
        self._test_fill_default_value(
            attr_info, {'key': constants.ATTR_NOT_SPECIFIED}, {})

        attr_info = {
            'key': {
                'allow_post': True,
            },
        }
        self._test_fill_default_value(attr_info, {'key': 'X'}, {'key': 'X'})
        self.assertRaises(ValueError, self._test_fill_default_value,
                          attr_info, {'key': 'X'}, {})
        self.assertRaises(self._EXC_CLS, attributes.fill_default_value,
                          attr_info, {}, self._EXC_CLS)
        attr_info = {
            'key': {
                'allow_post': False,
            },
        }
        self.assertRaises(ValueError, self._test_fill_default_value,
                          attr_info, {'key': 'X'}, {'key': 'X'})
        self._test_fill_default_value(attr_info, {}, {})
        self.assertRaises(self._EXC_CLS, attributes.fill_default_value,
                          attr_info, {'key': 'X'}, self._EXC_CLS)

    def _test_convert_value(self, attr_info, expected, res_dict):
        attributes.convert_value(attr_info, res_dict)
        self.assertEqual(expected, res_dict)

    def test_convert_value(self):
        attr_info = {
            'key': {
            },
        }
        self._test_convert_value(attr_info,
                                 {'key': constants.ATTR_NOT_SPECIFIED},
                                 {'key': constants.ATTR_NOT_SPECIFIED})
        self._test_convert_value(attr_info, {'key': 'X'}, {'key': 'X'})
        self._test_convert_value(attr_info,
                                 {'other_key': 'X'}, {'other_key': 'X'})

        attr_info = {
            'key': {
                'convert_to': converters.convert_to_int,
            },
        }
        self._test_convert_value(attr_info,
                                 {'key': constants.ATTR_NOT_SPECIFIED},
                                 {'key': constants.ATTR_NOT_SPECIFIED})
        self._test_convert_value(attr_info, {'key': 1}, {'key': '1'})
        self._test_convert_value(attr_info, {'key': 1}, {'key': 1})
        self.assertRaises(n_exc.InvalidInput, self._test_convert_value,
                          attr_info, {'key': 1}, {'key': 'a'})

        attr_info = {
            'key': {
                'validate': {'type:uuid': None},
            },
        }
        self._test_convert_value(attr_info,
                                 {'key': constants.ATTR_NOT_SPECIFIED},
                                 {'key': constants.ATTR_NOT_SPECIFIED})
        uuid_str = '01234567-1234-1234-1234-1234567890ab'
        self._test_convert_value(attr_info,
                                 {'key': uuid_str}, {'key': uuid_str})
        self.assertRaises(ValueError, self._test_convert_value,
                          attr_info, {'key': 1}, {'key': 1})
        self.assertRaises(self._EXC_CLS, attributes.convert_value,
                          attr_info, {'key': 1}, self._EXC_CLS)

    def test_populate_tenant_id(self):
        tenant_id_1 = uuidutils.generate_uuid()
        tenant_id_2 = uuidutils.generate_uuid()
        # apart from the admin, nobody can create a res on behalf of another
        # tenant
        ctx = context.Context(user_id=None, tenant_id=tenant_id_1)
        res_dict = {'tenant_id': tenant_id_2}
        self.assertRaises(webob.exc.HTTPBadRequest,
                          attributes.populate_tenant_id,
                          ctx, res_dict, None, None)
        ctx.is_admin = True
        self.assertIsNone(attributes.populate_tenant_id(ctx, res_dict,
                                                        None, None))

        # for each create request, the tenant_id should be added to the
        # req body
        res_dict2 = {}
        attributes.populate_tenant_id(ctx, res_dict2, None, True)
        self.assertEqual(
            {'tenant_id': ctx.tenant_id, 'project_id': ctx.tenant_id},
            res_dict2)

        # if the tenant_id is mandatory for the resource and not specified
        # in the request nor in the context, an exception should be raised
        res_dict3 = {}
        attr_info = {'tenant_id': {'allow_post': True}, }
        ctx.tenant_id = None
        self.assertRaises(webob.exc.HTTPBadRequest,
                          attributes.populate_tenant_id,
                          ctx, res_dict3, attr_info, True)


class TestHelpers(base.DietTestCase):

    def _verify_port_attributes(self, attrs):
        for test_attribute in ('id', 'name', 'mac_address', 'network_id',
                               'tenant_id', 'fixed_ips', 'status'):
            self.assertIn(test_attribute, attrs)

    def test_get_collection_info(self):
        attrs = attributes.get_collection_info('ports')
        self._verify_port_attributes(attrs)

    def test_get_collection_info_missing(self):
        self.assertFalse(attributes.get_collection_info('meh'))
