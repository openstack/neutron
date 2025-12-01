=======================================
Open vSwitch (OVS) and OVN requirements
=======================================

Neutron uses Open vSwitch with the ML2/openswitch and ML2/ovn mechanism
drivers. The latter also uses OVN. These are binary dependencies of a
Neutron deployment with some version constraints. In the table below we
hope to document the known minimum versions of OVS and OVN per Neutron
release. Or at least the minimum versions we know we used in our CI system
while developing.

We also have CI jobs to test with the main branch of OVS and OVN
therefore we feel no need to document the known maximum versions -
the newest OVS/OVN release should work.

.. warning::

   In releases 2024.1 and earlier it happened that different groups
   of CI jobs (or rather Zuul job templates: base, grenade, rally) used
   different OVS and OVN versions. Here we document only the base version,
   that is the version used in single and multinode tempest jobs. Stadium
   projects like ovn-bgp-agent may also have different requirements.

.. list-table:: OpenStack Neutron OVS/OVN Minimum Requirement Matrix

    * - OpenStack Release
      - Neutron Release
      - ``OVS_BRANCH``
      - ``OVN_BRANCH``
    * - 2025.2 (flamingo)
      - 27.0
      - branch-3.3
      - branch-24.03
    * - 2025.1 (epoxy)
      - 26.0
      - branch-3.3
      - branch-24.03
    * - 2024.2 (dalmatian)
      - 25.0
      - branch-3.3
      - branch-24.03
    * - 2024.1 (caracal)
      - 24.0
      - a4b04276ab5934d087669ff2d191a23931335c87
      - v21.06.0
    * - 2023.1 (antelope)
      - 22.0
      - a4b04276ab5934d087669ff2d191a23931335c87
      - v21.06.0
    * - zed
      - 21.0
      - a4b04276ab5934d087669ff2d191a23931335c87
      - v21.06.0
    * - yoga
      - 20.0
      - v2.16.0
      - v21.06.0
    * - xena
      - 19.0
      - v2.16.0
      - v21.06.0
    * - wallaby
      - 18.0
      - 0047ca3a0290f1ef954f2c76b31477cf4b9755f5
      - v20.06.1
    * - victoria
      - 17.0
      - 51e9479da62edb04a5be47a7655de75c299b9fa1
      - v20.06.1
