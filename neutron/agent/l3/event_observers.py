# Copyright 2014 OpenStack Foundation
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


class L3EventObservers(object):

    """Manages observers for L3 agent events."""

    def __init__(self):
        self.observers = set()

    def add(self, new_observer):
        """Add a listener for L3 agent notifications."""
        for observer in self.observers:
            if type(observer) == type(new_observer):
                raise ValueError('Only a single instance of AdvancedService '
                                 'may be registered, per type of service.')

        self.observers.add(new_observer)

    def notify(self, l3_event_action, *args, **kwargs):
        """Give interested parties a chance to act on event.

        NOTE: Preserves existing behavior for error propagation.
        """
        method_name = l3_event_action.__name__
        for observer in self.observers:
            getattr(observer, method_name)(*args, **kwargs)
