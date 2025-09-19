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

import netaddr
from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import provider_net as pnet
from neutron_lib import context
from oslo_utils import uuidutils

from neutron.objects import ports as port_obj
from neutron.plugins.ml2.extensions import dns_domain_keywords
from neutron.tests.unit.plugins.ml2.extensions import test_dns_integration


PROJECT_ID = uuidutils.generate_uuid()


class DNSDomainKeywordsTestCase(
        test_dns_integration.DNSIntegrationTestCase):

    _extension_drivers = ['dns_domain_keywords']
    _expected_dns_domain = "{}.{}".format(PROJECT_ID,
                                          test_dns_integration.DNSDOMAIN)

    def _create_port_for_test(self, provider_net=True, dns_domain=True,
                              dns_name=True, ipv4=True, ipv6=True,
                              dns_domain_port=False):
        net_kwargs = {}
        if provider_net:
            net_kwargs = {
                'arg_list': (pnet.NETWORK_TYPE, pnet.SEGMENTATION_ID,),
                pnet.NETWORK_TYPE: 'vxlan',
                pnet.SEGMENTATION_ID: '2016',
            }
        if dns_domain:
            net_kwargs[dns_apidef.DNSDOMAIN] = (
                "<project_id>.%s" % test_dns_integration.DNSDOMAIN)
            net_kwargs['arg_list'] = \
                net_kwargs.get('arg_list', ()) + (dns_apidef.DNSDOMAIN,)
        net_kwargs['shared'] = True
        res = self._create_network(self.fmt, 'test_network', True,
                                   as_admin=True, **net_kwargs)
        network = self.deserialize(self.fmt, res)
        if ipv4:
            cidr = '10.0.0.0/24'
            self._create_subnet_for_test(network['network']['id'], cidr)

        if ipv6:
            cidr = 'fd3d:bdd4:da60::/64'
            self._create_subnet_for_test(network['network']['id'], cidr)

        port_kwargs = {}
        if dns_name:
            port_kwargs = {
                'arg_list': (dns_apidef.DNSNAME,),
                dns_apidef.DNSNAME: test_dns_integration.DNSNAME
            }
        if dns_domain_port:
            port_kwargs[dns_apidef.DNSDOMAIN] = (
                test_dns_integration.PORTDNSDOMAIN)
            port_kwargs['arg_list'] = (port_kwargs.get('arg_list', ()) +
                                       (dns_apidef.DNSDOMAIN,))
        res = self._create_port('json', network['network']['id'],
                                set_context=True, tenant_id=PROJECT_ID,
                                **port_kwargs)
        self.assertEqual(201, res.status_int)
        port = self.deserialize(self.fmt, res)['port']
        ctx = context.get_admin_context()
        dns_data_db = port_obj.PortDNS.get_object(ctx, port_id=port['id'])
        return port, dns_data_db

    def _update_port_for_test(self, port,
                              new_dns_name=test_dns_integration.NEWDNSNAME,
                              new_dns_domain=None, **kwargs):
        test_dns_integration.mock_client.reset_mock()
        records_v4 = [ip['ip_address'] for ip in port['fixed_ips']
                      if netaddr.IPAddress(ip['ip_address']).version == 4]
        records_v6 = [ip['ip_address'] for ip in port['fixed_ips']
                      if netaddr.IPAddress(ip['ip_address']).version == 6]
        recordsets = []
        if records_v4:
            recordsets.append({'id': test_dns_integration.V4UUID,
                               'records': records_v4})
        if records_v6:
            recordsets.append({'id': test_dns_integration.V6UUID,
                               'records': records_v6})
        test_dns_integration.mock_client.recordsets.list.return_value = (
            recordsets)
        test_dns_integration.mock_admin_client.reset_mock()
        body = {}
        if new_dns_name is not None:
            body['dns_name'] = new_dns_name
        if new_dns_domain is not None:
            body[dns_apidef.DNSDOMAIN] = new_dns_domain
        body.update(kwargs)
        data = {'port': body}
        # NOTE(slaweq): Admin context is required here to be able to update
        # fixed_ips of the port as by default it is not possible for non-admin
        # users
        req = self.new_update_request('ports', data, port['id'],
                                      tenant_id=PROJECT_ID, as_admin=True)
        res = req.get_response(self.api)
        self.assertEqual(200, res.status_int)
        port = self.deserialize(self.fmt, res)['port']
        admin_ctx = context.get_admin_context()
        dns_data_db = port_obj.PortDNS.get_object(admin_ctx,
                                                  port_id=port['id'])
        return port, dns_data_db

    def _verify_port_dns(self, port, dns_data_db, dns_name=True,
                         dns_domain=True, ptr_zones=True, delete_records=False,
                         provider_net=True, dns_driver=True, original_ips=None,
                         current_dns_name=test_dns_integration.DNSNAME,
                         previous_dns_name='', dns_domain_port=False,
                         current_dns_domain=None, previous_dns_domain=None):
        current_dns_domain = current_dns_domain or self._expected_dns_domain
        previous_dns_domain = previous_dns_domain or self._expected_dns_domain
        super()._verify_port_dns(
            port=port, dns_data_db=dns_data_db, dns_name=dns_name,
            dns_domain=dns_domain, ptr_zones=ptr_zones,
            delete_records=delete_records, provider_net=provider_net,
            dns_driver=dns_driver, original_ips=original_ips,
            current_dns_name=current_dns_name,
            previous_dns_name=previous_dns_name,
            dns_domain_port=dns_domain_port,
            current_dns_domain=current_dns_domain,
            previous_dns_domain=previous_dns_domain)

    def test__parse_dns_domain(self, *mocks):
        ctx = context.Context(
            project_id=uuidutils.generate_uuid(),
            project_name="project",
            user_id=uuidutils.generate_uuid(),
            user_name="user"
        )
        domains = [
            ("<project_id>.<project_name>.<user_id>.<user_name>.domain",
             "{}.{}.{}.{}.domain".format(ctx.project_id, ctx.project_name,
                                         ctx.user_id, ctx.user_name)),
            ("<project_id>.domain",
             "%s.domain" % ctx.project_id),
            ("<project_name>.domain",
             "%s.domain" % ctx.project_name),
            ("<user_id>.domain",
             "%s.domain" % ctx.user_id),
            ("<user_name>.domain",
             "%s.domain" % ctx.user_name)]

        for domain, expected_domain in domains:
            self.assertEqual(
                expected_domain,
                dns_domain_keywords.DnsDomainKeywordsExtensionDriver.
                _parse_dns_domain(ctx, domain))

    def test__parse_dns_domain_missing_fields_in_context(self, *mocks):
        domain = "<project_id>.<project_name>.<user_id>.<user_name>.domain"
        ctx = context.Context(
            project_id=uuidutils.generate_uuid(),
            project_name=None,
            user_id=uuidutils.generate_uuid(),
            user_name="user"
        )
        expected_domain = "{}.<project_name>.{}.{}.domain".format(
            ctx.project_id, ctx.user_id, ctx.user_name)

        self.assertEqual(
            expected_domain,
            dns_domain_keywords.DnsDomainKeywordsExtensionDriver.
            _parse_dns_domain(ctx, domain))

    def test_update_port_with_current_dns_name(self, *mocks):
        port, dns_data_db = self._create_port_for_test()
        port, dns_data_db = self._update_port_for_test(
            port, new_dns_name=test_dns_integration.DNSNAME)
        self.assertEqual(test_dns_integration.DNSNAME,
                         dns_data_db['current_dns_name'])
        self.assertEqual(self._expected_dns_domain,
                         dns_data_db['current_dns_domain'])
        self.assertEqual('', dns_data_db['previous_dns_name'])
        self.assertEqual('', dns_data_db['previous_dns_domain'])
        self.assertFalse(
            test_dns_integration.mock_client.recordsets.create.call_args_list)
        self.assertFalse(
            test_dns_integration.mock_admin_client.recordsets.
            create.call_args_list)
        self.assertFalse(
            test_dns_integration.mock_client.recordsets.delete.call_args_list)
        self.assertFalse(
            test_dns_integration.mock_admin_client.recordsets.
            delete.call_args_list)

    def test_update_port_non_dns_name_attribute(self, *mocks):
        port, dns_data_db = self._create_port_for_test()
        port_name = 'port_name'
        kwargs = {'name': port_name}
        port, dns_data_db = self._update_port_for_test(port,
                                                       new_dns_name=None,
                                                       **kwargs)
        self.assertEqual(test_dns_integration.DNSNAME,
                         dns_data_db['current_dns_name'])
        self.assertEqual(self._expected_dns_domain,
                         dns_data_db['current_dns_domain'])
        self.assertEqual('', dns_data_db['previous_dns_name'])
        self.assertEqual('', dns_data_db['previous_dns_domain'])
        self.assertFalse(
            test_dns_integration.mock_client.recordsets.create.call_args_list)
        self.assertFalse(
            test_dns_integration.mock_admin_client.recordsets.
            create.call_args_list)
        self.assertFalse(
            test_dns_integration.mock_client.recordsets.delete.call_args_list)
        self.assertFalse(
            test_dns_integration.mock_admin_client.recordsets.
            delete.call_args_list)
        self.assertEqual(port_name, port['name'])
