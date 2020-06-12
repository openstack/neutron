# Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from oslo_config import cfg

from neutron._i18n import _

metering_agent_opts = [
    cfg.StrOpt('driver',
               default='neutron.services.metering.drivers.noop.'
               'noop_driver.NoopMeteringDriver',
               help=_("Metering driver")),
    cfg.IntOpt('measure_interval', default=30,
               help=_("Interval between two metering measures")),
    cfg.IntOpt('report_interval', default=300,
               help=_("Interval between two metering reports")),
    cfg.BoolOpt('granular_traffic_data',
                default=False,
                help=_("Defines if the metering agent driver should present "
                       "traffic data in a granular fashion, instead of "
                       "grouping all of the traffic data for all projects and "
                       "routers where the labels were assigned to. The "
                       "default value is `False` for backward compatibility."),
                ),
]


def register_metering_agent_opts(cfg=cfg.CONF):
    cfg.register_opts(metering_agent_opts)
