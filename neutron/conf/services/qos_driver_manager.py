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

from neutron._i18n import _

QOS_PLUGIN_OPTS = [
    cfg.ListOpt('notification_drivers',
                default=['message_queue'],
                help=_("Drivers list to use to send the update notification. "
                       "This option will be unused in Pike."),
                deprecated_for_removal=True),
]


def register_qos_plugin_opts(cfg=cfg.CONF):
    cfg.register_opts(QOS_PLUGIN_OPTS, "qos")
