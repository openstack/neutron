# Copyright 2012 VMware, Inc
#
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

from neutron.common import exceptions as n_exc


class NsxPluginException(n_exc.NeutronException):
    message = _("An unexpected error occurred in the NSX Plugin: %(err_msg)s")


class InvalidVersion(NsxPluginException):
    message = _("Unable to fulfill request with version %(version)s.")


class InvalidConnection(NsxPluginException):
    message = _("Invalid NSX connection parameters: %(conn_params)s")


class InvalidClusterConfiguration(NsxPluginException):
    message = _("Invalid cluster values: %(invalid_attrs)s. Please ensure "
                "that these values are specified in the [DEFAULT] "
                "section of the NSX plugin ini file.")


class InvalidNovaZone(NsxPluginException):
    message = _("Unable to find cluster config entry "
                "for nova zone: %(nova_zone)s")


class NoMorePortsException(NsxPluginException):
    message = _("Unable to create port on network %(network)s. "
                "Maximum number of ports reached")


class NatRuleMismatch(NsxPluginException):
    message = _("While retrieving NAT rules, %(actual_rules)s were found "
                "whereas rules in the (%(min_rules)s,%(max_rules)s) interval "
                "were expected")


class InvalidAttachmentType(NsxPluginException):
    message = _("Invalid NSX attachment type '%(attachment_type)s'")


class MaintenanceInProgress(NsxPluginException):
    message = _("The networking backend is currently in maintenance mode and "
                "therefore unable to accept requests which modify its state. "
                "Please try later.")


class L2GatewayAlreadyInUse(n_exc.Conflict):
    message = _("Gateway Service %(gateway)s is already in use")


class InvalidSecurityCertificate(NsxPluginException):
    message = _("An invalid security certificate was specified for the "
                "gateway device. Certificates must be enclosed between "
                "'-----BEGIN CERTIFICATE-----' and "
                "'-----END CERTIFICATE-----'")


class ServiceOverQuota(n_exc.Conflict):
    message = _("Quota exceeded for Vcns resource: %(overs)s: %(err_msg)s")


class RouterInUseByLBService(n_exc.InUse):
    message = _("Router %(router_id)s is in use by Loadbalancer Service "
                "%(vip_id)s")


class RouterInUseByFWService(n_exc.InUse):
    message = _("Router %(router_id)s is in use by firewall Service "
                "%(firewall_id)s")


class VcnsDriverException(NsxPluginException):
    message = _("Error happened in NSX VCNS Driver: %(err_msg)s")


class ServiceClusterUnavailable(NsxPluginException):
    message = _("Service cluster: '%(cluster_id)s' is unavailable. Please, "
                "check NSX setup and/or configuration")


class PortConfigurationError(NsxPluginException):
    message = _("An error occurred while connecting LSN %(lsn_id)s "
                "and network %(net_id)s via port %(port_id)s")

    def __init__(self, **kwargs):
        super(PortConfigurationError, self).__init__(**kwargs)
        self.port_id = kwargs.get('port_id')


class LsnNotFound(n_exc.NotFound):
    message = _('Unable to find LSN for %(entity)s %(entity_id)s')


class LsnPortNotFound(n_exc.NotFound):
    message = (_('Unable to find port for LSN %(lsn_id)s '
                 'and %(entity)s %(entity_id)s'))


class LsnMigrationConflict(n_exc.Conflict):
    message = _("Unable to migrate network '%(net_id)s' to LSN: %(reason)s")


class LsnConfigurationConflict(NsxPluginException):
    message = _("Configuration conflict on Logical Service Node %(lsn_id)s")
