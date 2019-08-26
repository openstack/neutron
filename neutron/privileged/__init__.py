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
