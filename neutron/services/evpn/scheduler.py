# Copyright 2026 Red Hat, LLC
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

import abc


class ChassisScheduler(abc.ABC):
    """Order chassis candidates for HA Chassis Group assignment."""
    # REVISIT: Refactor the OVNGatewayLeastLoadedScheduler class so it can be
    #          inherted here and its code reused.

    def select(self, candidates, existing_chassis=None, max_chassis=None):
        """Return an ordered list of chassis for HCG priority assignment.

        :param candidates: set of eligible chassis names
        :param existing_chassis: chassis already scheduled (kept at higher
                                 priority, not re-ordered)
        :param max_chassis: optional cap on total chassis count
                            (None = no cap, use all)
        :returns: ordered list -- first element gets highest priority
        """
        existing_chassis = existing_chassis or []
        existing_set = set(existing_chassis)
        new_candidates = candidates - existing_set
        if not new_candidates and not existing_chassis:
            return []
        ordered = self._order(new_candidates)
        result = existing_chassis + ordered
        if max_chassis is not None:
            result = result[:max_chassis]
        return result

    @abc.abstractmethod
    def _order(self, candidates):
        """Return candidates in the desired priority order."""


class LeastLoadedChassisScheduler(ChassisScheduler):
    """Order chassis candidates by load -- least loaded first.

    :param hcg_load: hcg load dictionary (chassis name -> load value)
    """

    def __init__(self, hcg_load):
        self._hcg_load = hcg_load

    def _load(self, chassis):
        return self._hcg_load.get(chassis, 0)

    def _order(self, candidates):
        return sorted(candidates, key=self._load)
