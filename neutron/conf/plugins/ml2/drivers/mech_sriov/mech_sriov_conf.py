# Copyright (c) 2018 Ericsson
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

from neutron._i18n import _


sriov_driver_opts = [
    cfg.ListOpt('vnic_type_prohibit_list',
                default=[],
                deprecated_name='vnic_type_blacklist',
                help=_("Comma-separated list of VNIC types for which support "
                       "is administratively prohibited by the mechanism "
                       "driver. Please note that the supported vnic_types "
                       "depend on your network interface card, on the kernel "
                       "version of your operating system, and on other "
                       "factors. "
                       "In the case of SRIOV mechanism drivers the valid "
                       "VNIC types are direct, macvtap and direct-physical.")),
]


def register_sriov_mech_driver_opts(cfg=cfg.CONF):
    cfg.register_opts(sriov_driver_opts, "SRIOV_DRIVER")
