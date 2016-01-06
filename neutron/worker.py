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

from oslo_service import service

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources


class NeutronWorker(service.ServiceBase):
    """Partial implementation of the ServiceBase ABC

    Subclasses will still need to add the other abstract methods defined in
    service.ServiceBase. See oslo_service for more details.

    If a plugin needs to handle synchronization with the Neutron database and
    do this only once instead of in every API worker, for instance, it would
    define a NeutronWorker class and the plugin would have get_workers return
    an array of NeutronWorker instances. For example:
        class MyPlugin(...):
            def get_workers(self):
                return [MyPluginWorker()]

        class MyPluginWorker(NeutronWorker):
            def start(self):
                super(MyPluginWorker, self).start()
                do_sync()
    """
    def start(self):
        registry.notify(resources.PROCESS, events.AFTER_CREATE, self.start)
