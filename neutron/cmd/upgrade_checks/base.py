# Copyright 2018 Red Hat Inc.
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

import abc


class BaseChecks(metaclass=abc.ABCMeta):

    """Base class providing upgrade checks.

    Stadium projects which want to provide their own upgrade checks to
    neutron-status CLI tool should inherit from this class.

    Each check method have to accept neutron.cmd.status.Checker
    class as an argument because all checks will be run in context of
    this class.
    """

    @abc.abstractmethod
    def get_checks(self):
        """Get tuple with check methods and check names to run."""
        pass
