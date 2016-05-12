..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


Calling the ML2 Plugin
======================

When writing code for an extension, service plugin, or any other part of
Neutron you must not call core plugin methods that mutate state while
you have a transaction open on the session that you pass into the core
plugin method.

The create and update methods for ports, networks, and subnets in ML2
all have a precommit phase and postcommit phase. During the postcommit
phase, the data is expected to be fully persisted to the database and
ML2 drivers will use this time to relay information to a backend outside
of Neutron. Calling the ML2 plugin within a transaction would violate
this semantic because the data would not be persisted to the DB; and,
were a failure to occur that caused the whole transaction to be rolled
back, the backend would become inconsistent with the state in Neutron's
DB.

To prevent this, these methods are protected with a decorator that will
raise a RuntimeError if they are called with context that has a session
in an active transaction. The decorator can be found at
neutron.common.utils.transaction_guard and may be used in other places
in Neutron to protect functions that are expected to be called outside
of a transaction.
