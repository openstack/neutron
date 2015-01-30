# Copyright (c) 2015 OpenStack Foundation
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

# TODO(armax): this file is added for bw-compat. As soon as the respective
# change merges on the networking_odl side, this file can be dropped.

from neutron.plugins.ml2.drivers.opendaylight import driver

OpenDaylightMechanismDriver = driver.OpenDaylightMechanismDriver
