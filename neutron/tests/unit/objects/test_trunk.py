# Copyright (c) 2016 Mirantis, Inc.
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

from neutron.objects import trunk as t_obj
from neutron.tests.unit.objects import test_base


class SubPortObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = t_obj.SubPort


class SubPortDbObjectTestCase(test_base.BaseDbObjectTestCase):

    _test_class = t_obj.SubPort


class TrunkObjectTestCase(test_base.BaseObjectIfaceTestCase):

    _test_class = t_obj.Trunk


class TrunkDbObjectTestCase(test_base.BaseDbObjectTestCase):

    _test_class = t_obj.Trunk
