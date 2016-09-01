# Copyright (c) 2015 OpenStack Foundation.  All rights reserved.
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

from neutron_lib.db import model_base
import sqlalchemy as sa

# Model classes for test resources


class MehModel(model_base.BASEV2, model_base.HasProject):
    meh = sa.Column(sa.String(8), primary_key=True)


class OtherMehModel(model_base.BASEV2, model_base.HasProject):
    othermeh = sa.Column(sa.String(8), primary_key=True)
