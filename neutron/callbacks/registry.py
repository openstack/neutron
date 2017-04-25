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

from neutron_lib.callbacks import registry

# NOTE(boden): This module will be removed soon; use neutron-lib callbacks

subscribe = registry.subscribe
unsubscribe = registry.unsubscribe
unsubscribe_by_resource = registry.unsubscribe_by_resource
unsubscribe_all = registry.unsubscribe_all
notify = registry.notify
clear = registry.clear
receives = registry.receives
has_registry_receivers = registry.has_registry_receivers
