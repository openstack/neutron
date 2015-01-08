# Copyright 2012 VMware, Inc.
# All Rights Reserved
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

from oslo_config import cfg

from neutron.i18n import _LI
from neutron.openstack.common import log as logging
from neutron.plugins.vmware.common import exceptions

LOG = logging.getLogger(__name__)
DEFAULT_PORT = 443
# Raise if one of those attributes is not specified
REQUIRED_ATTRIBUTES = ['default_tz_uuid', 'nsx_user',
                       'nsx_password', 'nsx_controllers']
# Emit a INFO log if one of those attributes is not specified
IMPORTANT_ATTRIBUTES = ['default_l3_gw_service_uuid']
# Deprecated attributes
DEPRECATED_ATTRIBUTES = ['metadata_dhcp_host_route',
                         'nvp_user', 'nvp_password', 'nvp_controllers']


class NSXCluster(object):
    """NSX cluster class.

    Encapsulates controller connections and the API client for a NSX cluster.

    Controller-specific parameters, such as timeouts are stored in the
    elements of the controllers attribute, which are dicts.
    """

    def __init__(self, **kwargs):
        self._required_attributes = REQUIRED_ATTRIBUTES[:]
        self._important_attributes = IMPORTANT_ATTRIBUTES[:]
        self._deprecated_attributes = {}
        self._sanity_check(kwargs)

        for opt, val in self._deprecated_attributes.iteritems():
            LOG.deprecated(_("Attribute '%s' has been deprecated or moved "
                             "to a new section. See new configuration file "
                             "for details."), opt)
            depr_func = getattr(self, '_process_%s' % opt, None)
            if depr_func:
                depr_func(val)

        # If everything went according to plan these two lists should be empty
        if self._required_attributes:
            raise exceptions.InvalidClusterConfiguration(
                invalid_attrs=self._required_attributes)
        if self._important_attributes:
            LOG.info(_LI("The following cluster attributes were "
                         "not specified: %s'"), self._important_attributes)
        # The API client will be explicitly created by users of this class
        self.api_client = None

    def _sanity_check(self, options):
        # Iterating this way ensures the conf parameters also
        # define the structure of this class
        for arg in cfg.CONF:
            if arg not in DEPRECATED_ATTRIBUTES:
                setattr(self, arg, options.get(arg, cfg.CONF.get(arg)))
                self._process_attribute(arg)
            elif options.get(arg) is not None:
                # Process deprecated attributes only if specified
                self._deprecated_attributes[arg] = options.get(arg)

    def _process_attribute(self, attribute):
        # Process the attribute only if it's not empty!
        if getattr(self, attribute, None):
            if attribute in self._required_attributes:
                self._required_attributes.remove(attribute)
            if attribute in self._important_attributes:
                self._important_attributes.remove(attribute)
            handler_func = getattr(self, '_process_%s' % attribute, None)
            if handler_func:
                handler_func()

    def _process_nsx_controllers(self):
        # If this raises something is not right, so let it bubble up
        # TODO(salvatore-orlando): Also validate attribute here
        for i, ctrl in enumerate(self.nsx_controllers or []):
            if len(ctrl.split(':')) == 1:
                self.nsx_controllers[i] = '%s:%s' % (ctrl, DEFAULT_PORT)

    def _process_nvp_controllers(self):
        self.nsx_controllers = self.nvp_controllers
        self._process_nsx_controllers()
