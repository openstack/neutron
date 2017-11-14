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


from neutron.db.port_security import models
from neutron.objects import base
from neutron.objects.extensions import port_security as base_ps


@base.NeutronObjectRegistry.register
class PortSecurity(base_ps._PortSecurity):
    # Version 1.0: Initial version
    VERSION = "1.0"

    fields_need_translation = {'id': 'port_id'}

    db_model = models.PortSecurityBinding
