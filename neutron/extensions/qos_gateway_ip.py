# Copyright 2018 OpenStack Foundation
# Copyright 2017 Letv Cloud Computing
# All Rights Reserved.
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

from neutron_lib.api.definitions import qos_gateway_ip as apidef
from neutron_lib.api import extensions


class Qos_gateway_ip(extensions.APIExtensionDescriptor):
    """Extension class supporting gateway IP rate limit in all router."""

    api_definition = apidef
