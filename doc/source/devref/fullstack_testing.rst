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


Full Stack Testing
==================

Goals
-----

* Stabilize the job:
    - Fix L3 HA failure
    - Look in to non-deterministic failures when adding a large amount of
      tests (Possibly bug 1486199).
    - Switch to kill signal 15 to terminate agents (Bug 1487548).
* Convert the L3 HA failover functional test to a full stack test
* Write DVR tests
* Write additional L3 HA tests
* Write a test that validates DVR + L3 HA integration after
  https://bugs.launchpad.net/neutron/+bug/1365473 is fixed.
