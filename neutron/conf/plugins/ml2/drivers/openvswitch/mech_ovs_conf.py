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


ovs_driver_opts = [
    cfg.ListOpt('vnic_type_prohibit_list',
                default=[],
                help=_("Comma-separated list of VNIC types for which support "
                       "is administratively prohibited by the mechanism "
                       "driver. Please note that the supported vnic_types "
                       "depend on your network interface card, on the kernel "
                       "version of your operating system, and on other "
                       "factors, like OVS version. In case of ovs mechanism "
                       "driver the valid vnic types are normal and direct. "
                       "Note that direct is supported only from kernel 4.8, "
                       "and from ovs 2.8.0. Bind DIRECT (SR-IOV) port allows "
                       "to offload the OVS flows using tc to the SR-IOV NIC. "
                       "This allows to support hardware offload via tc and "
                       "that allows us to manage the VF by OpenFlow control "
                       "plane using representor net-device.")),
]


def register_ovs_mech_driver_opts(cfg=cfg.CONF):
    cfg.register_opts(ovs_driver_opts, "OVS_DRIVER")
