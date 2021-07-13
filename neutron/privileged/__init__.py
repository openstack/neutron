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

from oslo_privsep import capabilities as caps
from oslo_privsep import priv_context

# It is expected that most (if not all) neutron operations can be
# executed with these privileges.
default = priv_context.PrivContext(
    __name__,
    cfg_section='privsep',
    pypath=__name__ + '.default',
    # TODO(gus): CAP_SYS_ADMIN is required (only?) for manipulating
    # network namespaces.  SYS_ADMIN is a lot of scary powers, so
    # consider breaking this out into a separate minimal context.
    capabilities=[caps.CAP_SYS_ADMIN,
                  caps.CAP_NET_ADMIN,
                  caps.CAP_DAC_OVERRIDE,
                  caps.CAP_DAC_READ_SEARCH,
                  caps.CAP_SYS_PTRACE],
)


dhcp_release_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_dhcp_release',
    pypath=__name__ + '.dhcp_release_cmd',
    capabilities=[caps.CAP_SYS_ADMIN,
                  caps.CAP_NET_ADMIN]
)


ovs_vsctl_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_ovs_vsctl',
    pypath=__name__ + '.ovs_vsctl_cmd',
    capabilities=[caps.CAP_SYS_ADMIN,
                  caps.CAP_NET_ADMIN]
)


namespace_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_namespace',
    pypath=__name__ + '.namespace_cmd',
    capabilities=[caps.CAP_SYS_ADMIN]
)


conntrack_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_conntrack',
    pypath=__name__ + '.conntrack_cmd',
    capabilities=[caps.CAP_NET_ADMIN]
)


link_cmd = priv_context.PrivContext(
    __name__,
    cfg_section='privsep_link',
    pypath=__name__ + '.link_cmd',
    capabilities=[caps.CAP_NET_ADMIN,
                  caps.CAP_SYS_ADMIN]
)
