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


Test Coverage
=============

The intention is to track merged features or areas of code that lack certain
types of tests. This document may be used both by developers that want to
contribute tests, and operators that are considering adopting a feature.

Coverage
--------

Note that while both API and scenario tests target a deployed OpenStack cloud,
API tests are under the Neutron tree and scenario tests are under the Tempest
tree.

It is the expectation that API changes involve API tests, agent features
or modifications involve functional tests, and Neutron-wide features involve
fullstack or scenario tests as appropriate.

The table references tests that explicitly target a feature, and not a job
that is configured to run against a specific backend (Thereby testing it
implicitly). So, for example, while the Linux bridge agent has a job that runs
the API and scenario tests with the Linux bridge agent configured, it does not
have functional tests that target the agent explicitly. The 'gate' column
is about running API/scenario tests with Neutron configured in a certain way,
such as what L2 agent to use or what type of routers to create.

* V            - Merged
* Blank        - Not applicable
* X            - Absent or lacking
* Patch number - Currently in review
* A name       - That person has committed to work on an item

+------------------------+------------+------------+------------+------------+------------+------------+
| Area                   | Unit       | Functional | API        | Fullstack  | Scenario   | Gate       |
+========================+============+============+============+============+============+============+
| DVR                    | Partial*   | L3-V OVS-X | V          | amuller    | X          | V          |
+------------------------+------------+------------+------------+------------+------------+------------+
| L3 HA                  | V          | V          | X          | 196393     | X          | X          |
+------------------------+------------+------------+------------+------------+------------+------------+
| L2pop                  | V          | X          |            | X          |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+
| DHCP HA                | V          |            |            | amuller    |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+
| OVS ARP responder      | V          | X*         |            | X*         |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+
| OVS agent              | V          | Partial    |            | V          |            | V          |
+------------------------+------------+------------+------------+------------+------------+------------+
| Linux Bridge agent     | V          | X          |            | X          |            | Non-voting |
+------------------------+------------+------------+------------+------------+------------+------------+
| Metering               | V          | X          | V          | X          |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+
| DHCP agent             | V          | 136834     |            | amuller    |            | V          |
+------------------------+------------+------------+------------+------------+------------+------------+
| rpc_workers            |            |            |            |            |            | X          |
+------------------------+------------+------------+------------+------------+------------+------------+
| Reference ipam driver  | V          |            |            |            |            | X (?)      |
+------------------------+------------+------------+------------+------------+------------+------------+
| MTU advertisement      | V          |            |            | X          |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+
| VLAN transparency      | V          |            | X          | X          |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+
| Prefix delegation      | V          | X          |            | X          |            |            |
+------------------------+------------+------------+------------+------------+------------+------------+

* DVR DB unit tests often assert that internal methods were called instead of
  testing functionality. A lot of our unit tests are flawed in this way,
  and DVR unit tests especially so. An attempt to remedy this was made
  in patch 178880.
* OVS ARP responder cannot be tested at the gate because the gate uses Ubuntu
  14.04 that only packages OVS 2.0. OVS added ARP manipulation support in
  version 2.1.
* Prefix delegation doesn't have functional tests for the dibbler and pd
  layers, nor for the L3 agent changes.

Missing Infrastructure
----------------------

The following section details missing test *types*. If you want to pick up
an action item, please contact amuller for more context and guidance.

* The Neutron team would like Rally to persist results over a window of time,
  graph and visualize this data, so that reviewers could compare average runs
  against a proposed patch.
* It's possible to test RPC methods via the unit tests infrastructure. This was
  proposed in patch 162811. The goal is provide developers a light weight
  way to rapidly run tests that target the RPC layer, so that a patch that
  modifies an RPC method's signature could be verified quickly and locally.
* Neutron currently does not test an in-place upgrade (Upgrading the server
  first, followed by agents one machine at a time). We make sure that the RPC
  layer remains backwards compatible manually via the review process but have
  no CI that verifies this.
