# Copyright 2013 vArmour Networks Inc.
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

from neutron.openstack.common import log as logging
from neutron.services.firewall.agents.varmour import varmour_api
from neutron.services.firewall.agents.varmour import varmour_utils as va_utils
from neutron.services.firewall.drivers import fwaas_base

LOG = logging.getLogger(__name__)


class vArmourFwaasDriver(fwaas_base.FwaasDriverBase):
    def __init__(self):
        LOG.debug(_("Initializing fwaas vArmour driver"))

        self.rest = varmour_api.vArmourRestAPI()

    def create_firewall(self, apply_list, firewall):
        LOG.debug(_('create_firewall (%s)'), firewall['id'])

        return self.update_firewall(apply_list, firewall)

    def update_firewall(self, apply_list, firewall):
        LOG.debug(_("update_firewall (%s)"), firewall['id'])

        if firewall['admin_state_up']:
            return self._update_firewall(apply_list, firewall)
        else:
            return self.apply_default_policy(apply_list, firewall)

    def delete_firewall(self, apply_list, firewall):
        LOG.debug(_("delete_firewall (%s)"), firewall['id'])

        return self.apply_default_policy(apply_list, firewall)

    def apply_default_policy(self, apply_list, firewall):
        LOG.debug(_("apply_default_policy (%s)"), firewall['id'])

        self.rest.auth()

        for ri in apply_list:
            self._clear_policy(ri, firewall)

        return True

    def _update_firewall(self, apply_list, firewall):
        LOG.debug(_("Updating firewall (%s)"), firewall['id'])

        self.rest.auth()

        for ri in apply_list:
            self._clear_policy(ri, firewall)
            self._setup_policy(ri, firewall)

        return True

    def _setup_policy(self, ri, fw):
        # create zones no matter if they exist. Interfaces are added by router
        body = {
            'type': 'L3',
            'interface': []
        }

        body['name'] = va_utils.get_trusted_zone_name(ri)
        self.rest.rest_api('POST', va_utils.REST_URL_CONF_ZONE, body)
        body['name'] = va_utils.get_untrusted_zone_name(ri)
        self.rest.rest_api('POST', va_utils.REST_URL_CONF_ZONE, body)
        self.rest.commit()

        servs = dict()
        addrs = dict()
        for rule in fw['firewall_rule_list']:
            if not rule['enabled']:
                continue

            if rule['ip_version'] == 4:
                service = self._make_service(ri, fw, rule, servs)
                s_addr = self._make_address(ri, fw, rule, addrs, True)
                d_addr = self._make_address(ri, fw, rule, addrs, False)

                policy = va_utils.get_firewall_policy_name(ri, fw, rule)
                z0 = va_utils.get_trusted_zone_name(ri)
                z1 = va_utils.get_untrusted_zone_name(ri)
                body = self._make_policy(policy + '_0', rule,
                                         z0, z0, s_addr, d_addr, service)
                self.rest.rest_api('POST', va_utils.REST_URL_CONF_POLICY, body)
                body = self._make_policy(policy + '_1', rule,
                                         z0, z1, s_addr, d_addr, service)
                self.rest.rest_api('POST', va_utils.REST_URL_CONF_POLICY, body)
                body = self._make_policy(policy + '_2', rule,
                                         z1, z0, s_addr, d_addr, service)
                self.rest.rest_api('POST', va_utils.REST_URL_CONF_POLICY, body)

                self.rest.commit()
            else:
                LOG.warn(_("Unsupported IP version rule."))

    def _clear_policy(self, ri, fw):
        prefix = va_utils.get_firewall_object_prefix(ri, fw)
        self.rest.del_cfg_objs(va_utils.REST_URL_CONF_POLICY, prefix)
        self.rest.del_cfg_objs(va_utils.REST_URL_CONF_ADDR, prefix)
        self.rest.del_cfg_objs(va_utils.REST_URL_CONF_SERVICE, prefix)

    def _make_service(self, ri, fw, rule, servs):
        prefix = va_utils.get_firewall_object_prefix(ri, fw)

        if rule.get('protocol'):
            key = rule.get('protocol')
            if rule.get('source_port'):
                key += '-' + rule.get('source_port')
            if rule.get('destination_port'):
                key += '-' + rule.get('destination_port')
        else:
            return

        if key in servs:
            name = '%s_%d' % (prefix, servs[key])
        else:
            # create new service object with index
            idx = len(servs)
            servs[key] = idx
            name = '%s_%d' % (prefix, idx)

            body = {'name': name}
            self.rest.rest_api('POST',
                               va_utils.REST_URL_CONF_SERVICE,
                               body)
            body = self._make_service_rule(rule)
            self.rest.rest_api('POST',
                               va_utils.REST_URL_CONF +
                               va_utils.REST_SERVICE_NAME % name,
                               body)
            self.rest.commit()

        return name

    def _make_service_rule(self, rule):
        body = {
            'name': '1',
            'protocol': rule.get('protocol')
        }
        if 'source_port' in rule:
            body['source-start'] = rule['source_port']
            body['source-end'] = rule['source_port']
        if 'destination_port' in rule:
            body['dest-start'] = rule['destination_port']
            body['dest-end'] = rule['destination_port']

        return body

    def _make_address(self, ri, fw, rule, addrs, is_src):
        prefix = va_utils.get_firewall_object_prefix(ri, fw)

        if is_src:
            key = rule.get('source_ip_address')
        else:
            key = rule.get('destination_ip_address')

        if not key:
            return

        if key in addrs:
            name = '%s_%d' % (prefix, addrs[key])
        else:
            # create new address object with idx
            idx = len(addrs)
            addrs[key] = idx
            name = '%s_%d' % (prefix, idx)

            body = {
                'name': name,
                'type': 'ipv4',
                'ipv4': key
            }
            self.rest.rest_api('POST', va_utils.REST_URL_CONF_ADDR, body)
            self.rest.commit()

        return name

    def _make_policy(self, name, rule, zone0, zone1, s_addr, d_addr, service):
        body = {
            'name': name,
            'action': 'permit' if rule.get('action') == 'allow' else 'deny',
            'from': zone0,
            'to': zone1,
            'match-source-address': [s_addr or 'Any'],
            'match-dest-address': [d_addr or 'Any'],
            'match-service': [service or 'Any']
        }

        return body
