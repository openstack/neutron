# Copyright (c) 2023 OpenStack Foundation.

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

import contextlib

from neutron_lib import constants as const
from oslo_utils import uuidutils
import webob.exc

from neutron.extensions import security_groups_default_rules as sgdf_ext
from neutron.tests.unit.extensions import test_securitygroup


DB_PLUGIN_KLASS = ('neutron.tests.unit.extensions.test_securitygroup.'
                   'SecurityGroupTestPlugin')


class DefaultSecurityGroupRulesTestExtensionManager(object):

    def get_resources(self):
        return sgdf_ext.Security_groups_default_rules.get_resources()

    def get_actions(self):
        return []

    def get_request_extensions(self):
        return []


class TestDefaultSecurityGroupRules(
        test_securitygroup.SecurityGroupDBTestCase):

    def setUp(self, plugin=None, ext_mgr=None):
        plugin = DB_PLUGIN_KLASS
        ext_mgr = DefaultSecurityGroupRulesTestExtensionManager()
        super(TestDefaultSecurityGroupRules, self).setUp(
            plugin=plugin, ext_mgr=ext_mgr)

    def _build_default_security_group_rule(
            self, direction, proto,
            port_range_min=None, port_range_max=None,
            remote_ip_prefix=None, remote_group_id=None,
            remote_address_group_id=None,
            used_in_default_sg=False,
            used_in_non_default_sg=True,
            description=None,
            ethertype=const.IPv4,
            as_admin=True):

        sg_rule_template = {
            'direction': direction,
            'protocol': proto,
            'ethertype': ethertype,
            'used_in_default_sg': used_in_default_sg,
            'used_in_non_default_sg': used_in_non_default_sg}

        if port_range_min:
            sg_rule_template['port_range_min'] = port_range_min

        if port_range_max:
            sg_rule_template['port_range_max'] = port_range_max

        if remote_ip_prefix:
            sg_rule_template['remote_ip_prefix'] = remote_ip_prefix

        if remote_group_id:
            sg_rule_template['remote_group_id'] = remote_group_id

        if remote_address_group_id:
            sg_rule_template['remote_address_group_id'] = (
                remote_address_group_id)

        if description:
            sg_rule_template['description'] = description

        return {'default_security_group_rule': sg_rule_template}

    def _create_default_security_group_rule(self, fmt, rules, as_admin=True,
                                            **kwargs):

        default_security_group_rule_req = self.new_create_request(
            'default-security-group-rules', rules, fmt, as_admin=as_admin)
        return default_security_group_rule_req.get_response(self.ext_api)

    def _make_default_security_group_rule(self, fmt, rules, as_admin=True,
                                          **kwargs):
        res = self._create_default_security_group_rule(
            self.fmt, rules, as_admin=as_admin)
        if res.status_int >= webob.exc.HTTPBadRequest.code:
            raise webob.exc.HTTPClientError(code=res.status_int)
        return self.deserialize(fmt, res)

    @contextlib.contextmanager
    def default_security_group_rule(self, direction='ingress',
                                    protocol=const.PROTO_NAME_TCP,
                                    port_range_min='22', port_range_max='22',
                                    remote_ip_prefix=None,
                                    remote_group_id=None,
                                    remote_address_group_id=None,
                                    used_in_default_sg=False,
                                    used_in_non_default_sg=True,
                                    description=None,
                                    fmt=None, ethertype=const.IPv4):
        if not fmt:
            fmt = self.fmt
        rule = self._build_default_security_group_rule(
                direction=direction,
                proto=protocol,
                port_range_min=port_range_min,
                port_range_max=port_range_max,
                remote_ip_prefix=remote_ip_prefix,
                remote_group_id=remote_group_id,
                remote_address_group_id=remote_address_group_id,
                used_in_default_sg=used_in_default_sg,
                used_in_non_default_sg=used_in_non_default_sg,
                description=description,
                ethertype=ethertype)
        default_security_group_rule = self._make_default_security_group_rule(
            self.fmt, rule)
        yield default_security_group_rule

    def test_create_default_security_group_rule(self):
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = const.PROTO_NAME_TCP
        port_range_min = 22
        port_range_max = 22
        keys = [('remote_ip_prefix', remote_ip_prefix),
                ('direction', direction),
                ('protocol', protocol),
                ('port_range_min', port_range_min),
                ('port_range_max', port_range_max)]

        with self.default_security_group_rule(
                direction=direction,
                protocol=protocol,
                port_range_min=port_range_min,
                port_range_max=port_range_max,
                remote_ip_prefix=remote_ip_prefix) as rule:
            for k, v, in keys:
                self.assertEqual(v, rule['default_security_group_rule'][k])

    def test_create_default_security_group_rule_ethertype_invalid_as_number(
            self):
        ethertype = 2
        rule = self._build_default_security_group_rule(
            'ingress', const.PROTO_NAME_TCP, '22',
            '22', None, None, ethertype=ethertype)
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_ethertype_invalid_for_protocol(
            self):
        rule = self._build_default_security_group_rule(
            'ingress', const.PROTO_NAME_IPV6_FRAG)
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_invalid_ip_prefix(self):
        for bad_prefix in ['bad_ip', 256, "2001:db8:a::123/129", '172.30./24']:
            rule = self._build_default_security_group_rule(
                'ingress',
                const.PROTO_NAME_TCP,
                '22', '22',
                bad_prefix)
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_invalid_ethertype_for_prefix(
            self):
        test_addr = {'192.168.1.1/24': 'IPv6',
                     '2001:db8:1234::/48': 'IPv4',
                     '192.168.2.1/24': 'BadEthertype'}
        for remote_ip_prefix, ethertype in test_addr.items():
            rule = self._build_default_security_group_rule(
                'ingress',
                const.PROTO_NAME_TCP,
                '22', '22',
                remote_ip_prefix,
                None,
                ethertype=ethertype)
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_with_unmasked_prefix(self):
        addr = {'10.1.2.3': {'mask': '32', 'ethertype': 'IPv4'},
                'fe80::2677:3ff:fe7d:4c': {'mask': '128', 'ethertype': 'IPv6'}}
        for remote_ip_prefix in addr:
            ethertype = addr[remote_ip_prefix]['ethertype']
            rule = self._build_default_security_group_rule(
                'ingress',
                const.PROTO_NAME_TCP,
                '22', '22',
                remote_ip_prefix,
                None,
                ethertype=ethertype)
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)
            res_sg = self.deserialize(self.fmt, res)
            prefix = res_sg['default_security_group_rule']['remote_ip_prefix']
            self.assertEqual('%s/%s' % (
                remote_ip_prefix, addr[remote_ip_prefix]['mask']), prefix)

    def test_create_default_security_group_rule_tcp_protocol_as_number(self):
        protocol = const.PROTO_NUM_TCP  # TCP
        rule = self._build_default_security_group_rule(
            'ingress', protocol, '22', '22')
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_default_security_group_rule_protocol_as_number(self):
        protocol = 2
        rule = self._build_default_security_group_rule(
            'ingress', protocol)
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_default_security_group_rule_proto_as_number_with_port_bad(
            self):
        # When specifying ports, neither can be None
        protocol = 6
        rule = self._build_default_security_group_rule(
            'ingress', protocol, '70', None)
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_protocol_as_number_range(self):
        # This is a SG rule with a port range, but treated as a single
        # port since min/max are the same.
        protocol = 6
        rule = self._build_default_security_group_rule(
            'ingress', protocol, '70', '70')
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPCreated.code, res.status_int)

    def test_create_default_security_group_rule_protocol_as_number_port_bad(
            self):
        # Only certain protocols support a SG rule with a port
        protocol = 111
        rule = self._build_default_security_group_rule(
            'ingress', protocol, '70', '70')
        res = self._create_default_security_group_rule(self.fmt, rule)
        self.deserialize(self.fmt, res)
        self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_case_insensitive(self):
        direction = "ingress"
        remote_ip_prefix = "10.0.0.0/24"
        protocol = 'TCP'
        port_range_min = 22
        port_range_max = 22
        ethertype = 'ipV4'
        with self.default_security_group_rule(
                direction=direction, protocol=protocol,
                port_range_min=port_range_min, port_range_max=port_range_max,
                remote_ip_prefix=remote_ip_prefix,
                ethertype=ethertype) as rule:

            # the lower case value will be return
            self.assertEqual(protocol.lower(),
                             rule['default_security_group_rule']['protocol'])
            self.assertEqual(const.IPv4,
                             rule['default_security_group_rule']['ethertype'])

    def test_create_default_security_group_rule_multiple_remotes(self):
        sg_id = uuidutils.generate_uuid()
        ag_id = uuidutils.generate_uuid()
        for remote in [
            {'remote_ip_prefix': '10.0.0.0/8', 'remote_group_id': sg_id},
            {'remote_group_id': sg_id, 'remote_address_group_id': ag_id},
            {'remote_ip_prefix': '10.0.0.0/8',
             'remote_address_group_id': ag_id},
            {'remote_ip_prefix': '10.0.0.0/8', 'remote_group_id': sg_id,
             'remote_address_group_id': ag_id}
        ]:
            rule = self._build_default_security_group_rule(
                "ingress", const.PROTO_NAME_TCP, **remote)
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_port_range_min_max_limits(
            self):
        direction = "ingress"
        protocol = const.PROTO_NAME_TCP
        port_range_min = const.PORT_RANGE_MIN
        port_range_max = const.PORT_RANGE_MAX
        # The returned rule should have port range min/max as None
        keys = [('direction', direction),
                ('protocol', protocol),
                ('port_range_min', None),
                ('port_range_max', None)]
        with self.default_security_group_rule(direction=direction,
                                              protocol=protocol,
                                              port_range_min=port_range_min,
                                              port_range_max=port_range_max
                                              ) as rule:
            for k, v, in keys:
                self.assertEqual(v, rule['default_security_group_rule'][k])

    def test_create_default_security_group_rule_duplicate_rules(self):
        with self.default_security_group_rule() as sgr:
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_TCP, '22', '22')
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
            self.assertIn(sgr['default_security_group_rule']['id'],
                          res.json['NeutronError']['message'])

    def test_default_create_security_group_rule_duplicate_rules_diff_desc(
            self):
        with self.default_security_group_rule() as sgr:
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_TCP, '22', '22')
            rule['default_security_group_rule']['description'] = "description"
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)
            self.assertIn(sgr['default_security_group_rule']['id'],
                          res.json['NeutronError']['message'])

    def test_create_default_security_group_rule_duplicate_rules_proto_name_num(
            self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_TCP, '22', '22')
            self._create_default_security_group_rule(self.fmt, rule)
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NUM_TCP, '22', '22')
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_default_security_group_rule_duplicate_rules_proto_num_name(
            self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NUM_UDP, '50', '100')
            self._create_default_security_group_rule(self.fmt, rule)
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_UDP, '50', '100')
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPConflict.code, res.status_int)

    def test_create_default_security_group_rule_min_port_greater_max(self):
        with self.default_security_group_rule():
            for protocol in [const.PROTO_NAME_TCP, const.PROTO_NAME_UDP,
                             const.PROTO_NUM_TCP, const.PROTO_NUM_UDP]:
                rule = self._build_default_security_group_rule(
                    'ingress', protocol, '50', '22')
                res = self._create_default_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code,
                                 res.status_int)

    def test_create_default_security_group_rule_ports_but_no_protocol(self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', None, '22', '22')
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_port_range_min_only(self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_TCP, '22', None)
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_port_range_max_only(self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_TCP, None, '22')
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_icmp_type_too_big(self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_ICMP, '256', None)
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_icmp_code_too_big(self):
        with self.default_security_group_rule():
            rule = self._build_default_security_group_rule(
                'ingress', const.PROTO_NAME_ICMP, '8', '256')
            res = self._create_default_security_group_rule(self.fmt, rule)
            self.deserialize(self.fmt, res)
            self.assertEqual(webob.exc.HTTPBadRequest.code, res.status_int)

    def test_create_default_security_group_rule_icmp_with_code_only(self):
        with self.default_security_group_rule():
            for code in ['2', '0']:
                rule = self._build_default_security_group_rule(
                    'ingress', const.PROTO_NAME_ICMP, None, code)
                res = self._create_default_security_group_rule(self.fmt, rule)
                self.deserialize(self.fmt, res)
                self.assertEqual(webob.exc.HTTPBadRequest.code,
                                 res.status_int)

    def test_list_defaut_security_group_rules(self):
        with self.default_security_group_rule(
                direction='egress', port_range_min=22,
                port_range_max=22) as rule1,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=23,
                    port_range_max=23) as rule2,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=24,
                    port_range_max=24) as rule3:

            self._test_list_resources('default-security-group-rule',
                                      [rule1, rule2, rule3],
                                      query_params='direction=egress')

    def test_list_defaut_security_group_rules_with_sort(self):
        with self.default_security_group_rule(
                direction='egress', port_range_min=22,
                port_range_max=22) as rule1,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=23,
                    port_range_max=23) as rule2,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=24,
                    port_range_max=24) as rule3:

            self._test_list_with_sort('default-security-group-rule',
                                      (rule3, rule2, rule1),
                                      [('port_range_max', 'desc')],
                                      query_params='direction=egress')

    def test_list_defaut_security_group_rules_with_pagination(self):
        with self.default_security_group_rule(
                direction='egress', port_range_min=22,
                port_range_max=22) as rule1,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=23,
                    port_range_max=23) as rule2,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=24,
                    port_range_max=24) as rule3:

            self._test_list_with_pagination(
                'default-security-group-rule', (rule3, rule2, rule1),
                ('port_range_max', 'desc'), 2, 2)

    def test_list_defaut_security_group_rules_with_pagination_reverse(self):
        with self.default_security_group_rule(
                direction='egress', port_range_min=22,
                port_range_max=22) as rule1,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=23,
                    port_range_max=23) as rule2,\
            self.default_security_group_rule(
                    direction='egress', port_range_min=24,
                    port_range_max=24) as rule3:

            self._test_list_with_pagination_reverse(
                'default-security-group-rule', (rule3, rule2, rule1),
                ('port_range_max', 'desc'), 2, 2)
