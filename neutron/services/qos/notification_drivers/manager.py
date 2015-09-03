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
from oslo_config import cfg
from oslo_log import log as logging

from neutron.i18n import _LI
from neutron import manager

QOS_DRIVER_NAMESPACE = 'neutron.qos.notification_drivers'
QOS_PLUGIN_OPTS = [
    cfg.ListOpt('notification_drivers',
                default='message_queue',
                help=_('Drivers list to use to send the update notification')),
]

cfg.CONF.register_opts(QOS_PLUGIN_OPTS, "qos")

LOG = logging.getLogger(__name__)


class QosServiceNotificationDriverManager(object):

    def __init__(self):
        self.notification_drivers = []
        self._load_drivers(cfg.CONF.qos.notification_drivers)

    def update_policy(self, context, qos_policy):
        for driver in self.notification_drivers:
            driver.update_policy(context, qos_policy)

    def delete_policy(self, context, qos_policy):
        for driver in self.notification_drivers:
            driver.delete_policy(context, qos_policy)

    def create_policy(self, context, qos_policy):
        for driver in self.notification_drivers:
            driver.create_policy(context, qos_policy)

    def _load_drivers(self, notification_drivers):
        """Load all the instances of the configured QoS notification drivers

        :param notification_drivers: comma separated string
        """
        if not notification_drivers:
            raise SystemExit(_('A QoS driver must be specified'))
        LOG.debug("Loading QoS notification drivers: %s", notification_drivers)
        for notification_driver in notification_drivers:
            driver_ins = self._load_driver_instance(notification_driver)
            self.notification_drivers.append(driver_ins)

    def _load_driver_instance(self, notification_driver):
        """Returns an instance of the configured QoS notification driver

        :returns: An instance of Driver for the QoS notification
        """
        mgr = manager.NeutronManager
        driver = mgr.load_class_for_provider(QOS_DRIVER_NAMESPACE,
                                             notification_driver)
        driver_instance = driver()
        LOG.info(
            _LI("Loading %(name)s (%(description)s) notification driver "
                "for QoS plugin"),
            {"name": notification_driver,
             "description": driver_instance.get_description()})
        return driver_instance
