# Copyright (c) 2016 IBM
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

import abc

from oslo_config import cfg
from oslo_log import log

from neutron import manager

LOG = log.getLogger(__name__)


class ExternalDNSService(metaclass=abc.ABCMeta):
    """Interface definition for an external dns service driver."""

    def __init__(self):
        """Initialize external dns service driver."""

    @classmethod
    def get_instance(cls):
        """Return an instance of the configured external DNS driver."""
        external_dns_driver_name = cfg.CONF.external_dns_driver
        mgr = manager.NeutronManager
        LOG.debug("Loading external dns driver: %s", external_dns_driver_name)
        driver_class = mgr.load_class_for_provider(
            'neutron.services.external_dns_drivers', external_dns_driver_name)
        return driver_class()

    @abc.abstractmethod
    def create_record_set(self, context, dns_domain, dns_name, records):
        """Create a record set in the specified zone.

        :param context: neutron api request context
        :type context: neutron_lib.context.Context
        :param dns_domain: the dns_domain where the record set will be created
        :type dns_domain: String
        :param dns_name: the name associated with the record set
        :type dns_name: String
        :param records: the records in the set
        :type records: List of Strings
        :raises: neutron.extensions.dns.DNSDomainNotFound
                 neutron.extensions.dns.DuplicateRecordSet
        """

    @abc.abstractmethod
    def delete_record_set(self, context, dns_domain, dns_name, records):
        """Delete a record set in the specified zone.

        :param context: neutron api request context
        :type context: neutron.context.Context
        :param dns_domain: the dns_domain from which the record set will be
         deleted
        :type dns_domain: String
        :param dns_name: the dns_name associated with the record set to be
         deleted
        :type dns_name: String
        :param records: the records in the set to be deleted
        :type records: List of Strings
        """
