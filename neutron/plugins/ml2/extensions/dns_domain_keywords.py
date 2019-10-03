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
from neutron_lib.api.definitions import dns_domain_keywords
from neutron_lib.api.definitions import dns_domain_ports as ports_apidef
from neutron_lib.api.definitions import subnet_dns_publish_fixed_ip as sn_dns
from neutron_lib import constants as lib_const
from oslo_log import log as logging

from neutron.plugins.ml2.extensions import subnet_dns_publish_fixed_ip

LOG = logging.getLogger(__name__)


class DnsDomainKeywordsExtensionDriver(
        subnet_dns_publish_fixed_ip.SubnetDNSPublishFixedIPExtensionDriver):

    _supported_extension_aliases = [dns_apidef.ALIAS,
                                    ports_apidef.ALIAS,
                                    sn_dns.ALIAS,
                                    dns_domain_keywords.ALIAS]

    def initialize(self):
        LOG.info("DnsDomainKeywordsExtensionDriver initialization complete")

    @staticmethod
    def _parse_dns_domain(plugin_context, domain):
        for keyword in lib_const.DNS_LABEL_KEYWORDS:
            keyword_value = getattr(plugin_context, keyword, None)
            if keyword_value is not None:
                domain = domain.replace('<' + keyword + '>', keyword_value)
            else:
                LOG.warning("Keyword <%s> does not have value in current "
                            "context and it will not be replaced in the "
                            "domain %s", keyword, domain)
        return domain
