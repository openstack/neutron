# Copyright 2014 Cisco Systems, Inc.  All rights reserved.
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

from neutron.openstack.common import excutils
from neutron.openstack.common import importutils
from neutron.openstack.common import log as logging
from neutron.plugins.cisco.cfg_agent import cfg_exceptions

LOG = logging.getLogger(__name__)


class DeviceDriverManager(object):
    """This class acts as a manager for device drivers.

    The device driver manager  maintains the relationship between the
    different neutron logical resource (eg: routers, firewalls, vpns etc.) and
    where they are hosted. For configuring a logical resource (router) in a
    hosting device, a corresponding device driver object is used.
    Device drivers encapsulate the necessary configuration information to
    configure a logical resource (eg: routers, firewalls, vpns etc.) on a
    hosting device (eg: CSR1kv).

    The device driver class loads one driver object per hosting device.
    The loaded drivers are cached in memory, so when a request is made to
    get driver object for the same hosting device and resource (like router),
    the existing driver object is reused.

    This class is used by the service helper classes.
    """

    def __init__(self):
        self._drivers = {}
        self._hosting_device_routing_drivers_binding = {}

    def get_driver(self, resource_id):
        try:
            return self._drivers[resource_id]
        except KeyError:
            with excutils.save_and_reraise_exception(reraise=False):
                raise cfg_exceptions.DriverNotFound(id=resource_id)

    def set_driver(self, resource):
        """Set the driver for a neutron resource.

        :param resource: Neutron resource in dict format. Expected keys:
                        { 'id': <value>
                          'hosting_device': { 'id': <value>, }
                          'router_type': {'cfg_agent_driver': <value>,  }
                        }
        :return driver : driver object
        """
        try:
            resource_id = resource['id']
            hosting_device = resource['hosting_device']
            hd_id = hosting_device['id']
            if hd_id in self._hosting_device_routing_drivers_binding:
                driver = self._hosting_device_routing_drivers_binding[hd_id]
                self._drivers[resource_id] = driver
            else:
                driver_class = resource['router_type']['cfg_agent_driver']
                driver = importutils.import_object(driver_class,
                                                   **hosting_device)
                self._hosting_device_routing_drivers_binding[hd_id] = driver
                self._drivers[resource_id] = driver
            return driver
        except ImportError:
            with excutils.save_and_reraise_exception(reraise=False):
                LOG.exception(_("Error loading cfg agent driver %(driver)s "
                                "for hosting device template "
                                "%(t_name)s(%(t_id)s)"),
                              {'driver': driver_class, 't_id': hd_id,
                               't_name': resource['name']})
                raise cfg_exceptions.DriverNotExist(driver=driver_class)
        except KeyError as e:
            with excutils.save_and_reraise_exception(reraise=False):
                raise cfg_exceptions.DriverNotSetForMissingParameter(e)

    def remove_driver(self, resource_id):
        """Remove driver associated to a particular resource."""
        if resource_id in self._drivers:
            del self._drivers[resource_id]

    def remove_driver_for_hosting_device(self, hd_id):
        """Remove driver associated to a particular hosting device."""
        if hd_id in self._hosting_device_routing_drivers_binding:
            del self._hosting_device_routing_drivers_binding[hd_id]
