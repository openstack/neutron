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

from neutron_lib.api.definitions import dns as dns_apidef
from neutron_lib.api.definitions import dns_domain_ports as ports_apidef
from neutron_lib.api.definitions import subnet_dns_publish_fixed_ip as sn_dns
from neutron_lib.api import validators
from oslo_log import log as logging

from neutron.objects import subnet as subnet_obj
from neutron.plugins.ml2.extensions import dns_integration as dns_int

LOG = logging.getLogger(__name__)


class SubnetDNSPublishFixedIPExtensionDriver(
        dns_int.DNSDomainPortsExtensionDriver):

    _supported_extension_aliases = [dns_apidef.ALIAS,
                                    ports_apidef.ALIAS,
                                    sn_dns.ALIAS]

    def initialize(self):
        LOG.info("SubnetDNSPublishFixedIPExtensionDriver initialization "
                 "complete")

    @property
    def extension_aliases(self):
        return self._supported_extension_aliases

    def extend_subnet_dict(self, session, db_data, response_data):
        # TODO(jh): This returns None instead of the proper response_data
        # response_data = (
        #     super(SubnetDNSPublishFixedIPExtensionDriver,
        #           self).extend_subnet_dict(
        #               session, db_data, response_data))
        response_data['dns_publish_fixed_ip'] = False
        if db_data.dns_publish_fixed_ip:
            response_data['dns_publish_fixed_ip'] = True
        return response_data

    def process_create_subnet(self, plugin_context, request_data, db_data):
        flag = request_data.get(sn_dns.DNS_PUBLISH_FIXED_IP)
        if not validators.is_attr_set(flag):
            return

        if flag:
            subnet_obj.SubnetDNSPublishFixedIP(
                    plugin_context,
                    subnet_id=db_data['id'],
                    dns_publish_fixed_ip=flag).create()
        db_data[sn_dns.DNS_PUBLISH_FIXED_IP] = flag

    def process_update_subnet(self, plugin_context, request_data, db_data):
        new_value = request_data.get(sn_dns.DNS_PUBLISH_FIXED_IP)
        if not validators.is_attr_set(new_value):
            return

        current_value = db_data.get(sn_dns.DNS_PUBLISH_FIXED_IP)
        if current_value == new_value:
            return

        subnet_id = db_data['id']
        if new_value:
            subnet_obj.SubnetDNSPublishFixedIP(
                    plugin_context,
                    subnet_id=subnet_id,
                    dns_publish_fixed_ip=new_value).create()
        else:
            sn_obj = subnet_obj.SubnetDNSPublishFixedIP.get_object(
                    plugin_context,
                    subnet_id=subnet_id)
            sn_obj.delete()
        db_data[sn_dns.DNS_PUBLISH_FIXED_IP] = new_value
