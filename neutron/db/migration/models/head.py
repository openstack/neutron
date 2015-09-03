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

from neutron.db import address_scope_db  # noqa
from neutron.db import agents_db  # noqa
from neutron.db import agentschedulers_db  # noqa
from neutron.db import allowedaddresspairs_db  # noqa
from neutron.db import dvr_mac_db  # noqa
from neutron.db import external_net_db  # noqa
from neutron.db import extradhcpopt_db  # noqa
from neutron.db import extraroute_db  # noqa
from neutron.db import flavors_db  # noqa
from neutron.db import l3_agentschedulers_db  # noqa
from neutron.db import l3_attrs_db  # noqa
from neutron.db import l3_db  # noqa
from neutron.db import l3_dvrscheduler_db  # noqa
from neutron.db import l3_gwmode_db  # noqa
from neutron.db import l3_hamode_db  # noqa
from neutron.db.metering import metering_db  # noqa
from neutron.db import model_base
from neutron.db import models_v2  # noqa
from neutron.db import portbindings_db  # noqa
from neutron.db import portsecurity_db  # noqa
from neutron.db.qos import models as qos_models  # noqa
from neutron.db.quota import models  # noqa
from neutron.db import rbac_db_models  # noqa
from neutron.db import securitygroups_db  # noqa
from neutron.db import servicetype_db  # noqa
from neutron.ipam.drivers.neutrondb_ipam import db_models  # noqa
from neutron.plugins.bigswitch.db import consistency_db  # noqa
from neutron.plugins.bigswitch import routerrule_db  # noqa
from neutron.plugins.brocade.db import models as brocade_models  # noqa
from neutron.plugins.cisco.db.l3 import l3_models  # noqa
from neutron.plugins.cisco.db import n1kv_models_v2  # noqa
from neutron.plugins.cisco.db import network_models_v2  # noqa
from neutron.plugins.ml2.drivers.brocade.db import (  # noqa
    models as ml2_brocade_models)
from neutron.plugins.ml2.drivers import type_flat  # noqa
from neutron.plugins.ml2.drivers import type_geneve  # noqa
from neutron.plugins.ml2.drivers import type_gre  # noqa
from neutron.plugins.ml2.drivers import type_vlan  # noqa
from neutron.plugins.ml2.drivers import type_vxlan  # noqa
from neutron.plugins.ml2 import models  # noqa
from neutron.plugins.nuage import nuage_models  # noqa


def get_metadata():
    return model_base.BASEV2.metadata
