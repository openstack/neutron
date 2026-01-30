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
#

import abc
import copy
import secrets

from oslo_log import log

from neutron.common.ovn import constants as ovn_const
from neutron.common.ovn import utils
from neutron.common import utils as common_utils
from neutron.conf.plugins.ml2.drivers.ovn import ovn_conf


LOG = log.getLogger(__name__)


class OVNGatewayScheduler(metaclass=abc.ABCMeta):

    def __init__(self):
        pass

    @abc.abstractmethod
    def select(self, nb_idl, sb_idl, gateway_name, candidates=None,
               existing_chassis=None, target_lrouter=None):
        """Schedule the gateway port of a router to an OVN chassis.

        Schedule the gateway router port only if it is not already
        scheduled.
        """

    @staticmethod
    def filter_existing_chassis(gw_chassis, physnet, chassis_physnets,
                                existing_chassis, az_hints, chassis_with_azs):
        chassis_list = copy.copy(existing_chassis)
        for chassis_name in existing_chassis or []:
            if utils.is_gateway_chassis_invalid(chassis_name, gw_chassis,
                                                physnet, chassis_physnets,
                                                az_hints, chassis_with_azs):
                LOG.debug("Chassis %(chassis)s is invalid for scheduling "
                          "router in physnet: %(physnet)s.",
                          {'chassis': chassis_name,
                           'physnet': physnet})
                chassis_list.remove(chassis_name)
        return chassis_list

    def _schedule_gateway(self, nb_idl, sb_idl, gateway_name, candidates,
                          existing_chassis, target_lrouter):
        existing_chassis = existing_chassis or []
        candidates = candidates or []
        candidates = list(set(candidates) - set(existing_chassis))
        # If no candidates, or gateway scheduled on MAX_GW_CHASSIS nodes
        # or all candidates in existing_chassis, return existing_chassis.
        # Otherwise, if more candidates present, then schedule them.
        if existing_chassis:
            if not candidates or (
                    len(existing_chassis) == ovn_const.MAX_GW_CHASSIS):
                return existing_chassis
        if not candidates:
            LOG.warning('Gateway %s was not scheduled on any chassis, no '
                        'candidates are available', gateway_name)
            return
        chassis_count = min(
            ovn_const.MAX_GW_CHASSIS - len(existing_chassis),
            len(candidates)
        )
        # The actual binding of the gateway to a chassis via the options
        # column or gateway_chassis column in the OVN_Northbound is done
        # by the caller
        chassis = self._select_gateway_chassis(
            nb_idl, sb_idl, candidates, 1, chassis_count, target_lrouter
        )[:chassis_count]
        # priority of existing chassis is higher than candidates
        chassis = existing_chassis + chassis

        LOG.debug("Gateway %s scheduled on chassis %s",
                  gateway_name, chassis)
        return chassis

    def _reorder_by_az(self, nb_idl, sb_idl, candidates):
        chassis_selected = []
        other_chassis = []
        azs = set()

        # Check if candidates list valid
        if not candidates:
            return candidates

        chassis_with_azs = sb_idl.get_chassis_and_azs()

        # Get list of all AZs
        for chassis in candidates:
            try:
                azs.update(chassis_with_azs[chassis])
            except KeyError:
                continue

        for chassis in candidates:
            # Verify if chassis is in an AZ not already used
            # and delete AZs of chassis from list
            try:
                chassis_azs = chassis_with_azs[chassis]
                if azs.intersection(chassis_azs):
                    azs = azs.difference(chassis_azs)
                    chassis_selected += [chassis]
                else:
                    other_chassis += [chassis]
            except KeyError:
                other_chassis += [chassis]

        chassis_selected += other_chassis

        return chassis_selected

    @abc.abstractmethod
    def _select_gateway_chassis(self, nb_idl, sb_idl, candidates,
                                priority_min, priority_max, target_lrouter):
        """Choose a chassis from candidates based on a specific policy.

        Returns a list of chassis to use for scheduling. The value at
        ``ret[0]`` will be used for the chassis with ``priority_max``, the
        value at ``ret[-1]`` will be used for the chassis with ``priority_min``
        """


class OVNGatewayChanceScheduler(OVNGatewayScheduler):
    """Randomly select an chassis for a gateway port of a router"""

    def select(self, nb_idl, sb_idl, gateway_name, candidates=None,
               existing_chassis=None, target_lrouter=None):
        return self._schedule_gateway(
            nb_idl, sb_idl, gateway_name,
            candidates, existing_chassis, target_lrouter)

    def _select_gateway_chassis(self, nb_idl, sb_idl, candidates,
                                priority_min, priority_max, target_lrouter):
        candidates = copy.deepcopy(candidates)
        secrets.SystemRandom().shuffle(candidates)
        return self._reorder_by_az(nb_idl, sb_idl, candidates)


class OVNGatewayLeastLoadedScheduler(OVNGatewayScheduler):
    """Select the least loaded chassis for a gateway port of a router"""

    def select(self, nb_idl, sb_idl, gateway_name, candidates=None,
               existing_chassis=None, target_lrouter=None):
        return self._schedule_gateway(nb_idl, sb_idl, gateway_name,
                                      candidates, existing_chassis,
                                      target_lrouter)

    def _select_gateway_chassis(self, nb_idl, sb_idl, candidates,
                                priority_min, priority_max, target_lrouter):
        """Returns a lit of chassis from candidates ordered by priority
        (highest first). Each chassis in every priority will be selected, as it
        is the least loaded for that specific priority.
        """
        selected_chassis = []
        priorities = list(range(priority_max, priority_min - 1, -1))
        all_chassis_bindings = nb_idl.get_all_chassis_gateway_bindings(
                candidates, priorities=priorities)

        anti_affinity_score = 0
        chassis_hosting_lr = []

        # For the chassis already hosting different ports of this router,
        # we want to decrease the likelyhood to be selected.
        # Here we calculate the chassis_hosting_lr and prepare the
        # anti_affinity_score to be used later in the loop.
        lrouter_ports = getattr(target_lrouter, 'ports', set())
        if len(lrouter_ports):
            lrouter_ports_names = {getattr(lrp, 'name', "")
                                   for lrp in lrouter_ports}
            chassis_hosting_lr = [chassis
                for chassis, lrps in all_chassis_bindings.items() if
                not lrouter_ports_names.isdisjoint(
                    [lrp_name for lrp_name, prio in lrps])]

            # The `MAX_GW_CHASSIS` constant here is used mostly to get a
            # multiplier that guarantees our score will outweigh natural
            # LRP priority so that when other chassis are available those
            # will be chosen rather than a chassis already hosting a LRP
            # for this LR.
            anti_affinity_score = (ovn_const.MAX_GW_CHASSIS *
                                   len(target_lrouter.ports))

        # ``leastloaded_chassis`` will contain, in decreasing order, a list of
        # groups of chassis that are the least loaded chassis for each
        # priority. E.g.: [(ch1, ch2),  # prio3
        #                  (ch3, ch2),  # prio2
        #                  (ch1, ch3)]  # prio1
        # ``discarded_by_priority`` will contain the other chassis discarded
        # in the same priority.
        leastloaded_by_priority = []
        discarded_by_priority = []
        for priority in priorities:
            chassis_load = {}
            for chassis, lrps in all_chassis_bindings.items():
                lrps_with_prio = 0
                for lrp, prio in lrps:
                    if prio == priority:
                        lrps_with_prio += 1

                # If the chassis is already hosting another LRP, increase the
                # load value adding ``anti_affinity_score``.
                if chassis in chassis_hosting_lr:
                    chassis_load[chassis] = (lrps_with_prio +
                                             anti_affinity_score)
                else:
                    chassis_load[chassis] = lrps_with_prio
            if len(chassis_load) == 0:
                break

            leastload = min(chassis_load.values())
            # Store only the least loaded chassis.
            leastloaded_set = {chassis for chassis, load in
                               chassis_load.items() if load == leastload}
            leastloaded_by_priority.append(leastloaded_set)
            discarded_by_priority.append(set(chassis_load) - leastloaded_set)

        selected_chassis = common_utils.find_unique_sequence(
            leastloaded_by_priority)

        if not selected_chassis:
            # This loop will add the discarded chassis to the lower priorities,
            # in order.
            for idx in reversed(range(len(priorities))):
                leastloaded_by_priority[idx] |= discarded_by_priority[idx]
                selected_chassis = common_utils.find_unique_sequence(
                    leastloaded_by_priority)
                if selected_chassis:
                    break

        return self._reorder_by_az(nb_idl, sb_idl, selected_chassis)


OVN_SCHEDULER_STR_TO_CLASS = {
    ovn_const.OVN_L3_SCHEDULER_CHANCE: OVNGatewayChanceScheduler,
    ovn_const.OVN_L3_SCHEDULER_LEASTLOADED: OVNGatewayLeastLoadedScheduler}


def get_scheduler():
    return OVN_SCHEDULER_STR_TO_CLASS[ovn_conf.get_ovn_l3_scheduler()]()
