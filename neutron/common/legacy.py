# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 New Dream Network, LLC (DreamHost)
# All Rights Reserved.
#
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

# @author Mark McClain (DreamHost)

from oslo.config import cfg

from neutron.openstack.common import log as logging

LOG = logging.getLogger(__name__)


def scrub_class_path(cls_path):
    """Scrub from Quantum from old class_path references."""

    if isinstance(cls_path, basestring):
        if cls_path.startswith('quantum'):
            new_path = cls_path.replace('quantum', 'neutron')
            new_path = new_path.replace('Quantum', 'Neutron')
            LOG.warn(
                _("Old class module path in use.  Please change '%(old)s' "
                  "to '%(new)s'."),
                {'old': cls_path, 'new': new_path}
            )
            cls_path = new_path
    return cls_path


def override_config(config, config_keys=None):
    """Attempt to override config_key with Neutron compatible values."""

    for key in config_keys:
        group = None
        if not isinstance(key, basestring):
            try:
                group, key, module_str = key
                old_value = getattr(getattr(config, group), key, None)
            except AttributeError:
                try:
                    config.import_opt(key, module_str, group)
                    old_value = getattr(getattr(config, group), key, None)
                except (cfg.NoSuchOptError,
                        cfg.NoSuchGroupError,
                        AttributeError):
                    LOG.warn(_('Key %(key)s in group %(group)s is unknown. '
                               'It may not be defined or needed by this '
                               'service.') % {'key': key, 'group': group})
                    continue
        else:
            old_value = getattr(config, key, None)
        if not old_value:
            continue
        elif isinstance(old_value, list):
            new_value = [scrub_class_path(v) for v in old_value]
        else:
            new_value = scrub_class_path(old_value)

        if new_value != old_value:
            config.set_override(key, new_value, group=group)


def modernize_quantum_config(config):
    """Updates keys from old Quantum configurations for Neutron."""
    config_keys = [
        'allowed_rpc_exception_modules',
        'core_plugin',
        'device_driver',
        'dhcp_driver',
        'driver_fqn',
        'interface_driver',
        'network_scheduler_driver',
        'notification_driver',
        'router_scheduler_driver',
        'rpc_backend',
        'service_plugins',
        ('SECURITYGROUP',
         'firewall_driver',
         'neutron.agent.securitygroups_rpc'),
    ]

    override_config(config, config_keys)
