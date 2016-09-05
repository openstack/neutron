# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from neutron.services.trunk.drivers import base


class FakeDriver(base.DriverBase):

    @property
    def is_loaded(self):
        return True

    @classmethod
    def create(cls):
        return cls('foo_name', ('foo_intfs',), ('foo_seg_types',))


class FakeDriver2(base.DriverBase):

    @property
    def is_loaded(self):
        return True

    @classmethod
    def create(cls):
        return cls('foo_name2', ('foo_intf2',), ('foo_seg_types2',))


class FakeDriverCanTrunkBoundPort(base.DriverBase):

    @property
    def is_loaded(self):
        return True

    @classmethod
    def create(cls):
        return cls('foo_name3', ('foo_intfs',),
                   ('foo_seg_types',), can_trunk_bound_port=True)


class FakeDriverWithAgent(base.DriverBase):

    @property
    def is_loaded(self):
        return True

    @classmethod
    def create(cls):
        return cls('foo_name4', ('foo_intfs',), ('foo_seg_types',), "foo_type")
