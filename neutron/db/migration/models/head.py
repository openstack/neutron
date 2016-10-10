# Copyright (c) 2014 OpenStack Foundation.
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

"""
The module provides all database models at current HEAD.

Its purpose is to create comparable metadata with current database schema.
Based on this comparison database can be healed with healing migration.

"""

import os.path

from neutron_lib.db import model_base

from neutron.common import utils
from neutron.db import agentschedulers_db  # noqa
from neutron.db.extra_dhcp_opt import models as edo_models  # noqa
from neutron.db import l3_dvrscheduler_db  # noqa
from neutron.db import l3_gwmode_db  # noqa
from neutron.db import models
from neutron.db import models_v2  # noqa
from neutron.db.port_security import models as ps_models  # noqa
from neutron.db.qos import models as qos_models  # noqa
from neutron.db.quota import models as quota_models  # noqa
from neutron.db import rbac_db_models  # noqa
from neutron.ipam.drivers.neutrondb_ipam import db_models  # noqa
from neutron.plugins.ml2 import models as ml2_models  # noqa
from neutron.services.auto_allocate import models as aa_models  # noqa
from neutron.services.trunk import models as trunk_models  # noqa


utils.import_modules_recursively(os.path.dirname(models.__file__))


def get_metadata():
    return model_base.BASEV2.metadata
