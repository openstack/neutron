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

from oslo_log import log as logging
from oslo_utils import excutils


from neutron._i18n import _LE, _LW
from neutron.api.rpc.callbacks import events as rpc_events
from neutron.api.rpc.callbacks.producer import registry as rpc_registry
from neutron.api.rpc.callbacks import resources
from neutron.api.rpc.handlers import resources_rpc
from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.conf.services import qos_driver_manager as qos_mgr
from neutron.objects.qos import policy as policy_object
from neutron.services.qos import qos_consts

qos_mgr.register_qos_plugin_opts()

LOG = logging.getLogger(__name__)


class QosServiceDriverManager(object):

    def __init__(self, enable_rpc=False):
        self._drivers = []
        self.notification_api = resources_rpc.ResourcesPushRpcApi()
        #TODO(mangelajo): remove the enable_rpc parameter in Pike since
        #                 we only use it when a message_queue derived driver
        #                 is found in the notification_drivers
        self.rpc_notifications_required = enable_rpc
        rpc_registry.provide(self._get_qos_policy_cb, resources.QOS_POLICY)
        # notify any registered QoS driver that we're ready, those will
        # call the driver manager back with register_driver if they
        # are enabled
        registry.notify(qos_consts.QOS_PLUGIN, events.AFTER_INIT, self)

        if self.rpc_notifications_required:
            self.push_api = resources_rpc.ResourcesPushRpcApi()

    @staticmethod
    def _get_qos_policy_cb(resource, policy_id, **kwargs):
        context = kwargs.get('context')
        if context is None:
            LOG.warning(_LW(
                'Received %(resource)s %(policy_id)s without context'),
                {'resource': resource, 'policy_id': policy_id}
            )
            return

        policy = policy_object.QosPolicy.get_object(context, id=policy_id)
        return policy

    def call(self, method_name, *args, **kwargs):
        """Helper method for calling a method across all extension drivers."""
        for driver in self._drivers:
            try:
                getattr(driver, method_name)(*args, **kwargs)
            except Exception:
                with excutils.save_and_reraise_exception():
                    LOG.exception(_LE("Extension driver '%(name)s' failed in "
                                      "%(method)s"),
                                  {'name': driver.name, 'method': method_name})

        if self.rpc_notifications_required:
            context = kwargs.get('context') or args[0]
            policy_obj = kwargs.get('policy_obj') or args[1]

            # we don't push create_policy events since policies are empty
            # on creation, they only become of any use when rules get
            # attached to them.
            if method_name == 'update_policy':
                self.push_api.push(context, [policy_obj], rpc_events.UPDATED)

            elif method_name == 'delete_policy':
                self.push_api.push(context, [policy_obj], rpc_events.DELETED)

    def register_driver(self, driver):
        """Register driver with qos plugin.

        This method is called from drivers on INIT event.
        """
        self._drivers.append(driver)
        self.rpc_notifications_required |= driver.requires_rpc_notifications

    @property
    def supported_rule_types(self):
        if not self._drivers:
            return []

        rule_types = set(qos_consts.VALID_RULE_TYPES)

        # Recalculate on every call to allow drivers determine supported rule
        # types dynamically
        for driver in self._drivers:
            new_rule_types = rule_types & set(driver.supported_rules)
            dropped_rule_types = rule_types - new_rule_types
            if dropped_rule_types:
                LOG.debug("%(rule_types)s rule types disabled "
                          "because enabled %(driver)s does not support them",
                          {'rule_types': ', '.join(dropped_rule_types),
                           'driver': driver.name})
            rule_types = new_rule_types

        LOG.debug("Supported QoS rule types "
                  "(common subset for all loaded QoS drivers): %s", rule_types)
        return rule_types
