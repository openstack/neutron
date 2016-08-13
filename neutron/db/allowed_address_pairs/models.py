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

import sys

from neutron.common import _deprecate
from neutron.db.models import allowed_address_pair as aap_models


# WARNING: THESE MUST BE THE LAST TWO LINES IN THIS MODULE
_OLD_REF = sys.modules[__name__]
sys.modules[__name__] = _deprecate._DeprecateSubset(globals(), aap_models)
# WARNING: THESE MUST BE THE LAST TWO LINES IN THIS MODULE
