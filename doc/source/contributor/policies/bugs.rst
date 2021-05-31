.. _neutron_bugs:

Neutron Bugs
============

Neutron (client, core, VPNaaS) maintains all of its bugs in the following
Launchpad projects:

* `Launchpad Neutron <https://bugs.launchpad.net/neutron>`_
* `Launchpad python-neutronclient <https://bugs.launchpad.net/python-neutronclient>`_


Neutron Bugs Team In Launchpad
------------------------------

The `Neutron Bugs <https://launchpad.net/~neutron-bugs>`_ team in Launchpad
is used to allow access to the projects above. Members of the above group
have the ability to set bug priorities, target bugs to releases, and other
administrative tasks around bugs. The administrators of this group are the
members of the `neutron-drivers-core
<https://review.opendev.org/#/admin/groups/464,members>`_ gerrit group.
Non administrators of this group include anyone who is involved with the
Neutron project and has a desire to assist with bug triage.

If you would like to join this Launchpad group, it's best to reach out to a
member of the above mentioned neutron-drivers-core team in #openstack-neutron
on OFTC and let them know why you would like to be a member. The team is
more than happy to add additional bug triage capability, but it helps to know
who is requesting access, and IRC is a quick way to make the connection.

As outlined below the bug deputy is a volunteer who wants to help with defect
management. Permissions will have to be granted assuming that people sign up
on the deputy role. The permission won't be given freely, a person must show
some degree of prior involvement.

.. _neutron_bug_deputy:

Neutron Bug Deputy
------------------

Neutron maintains the notion of a "bug deputy". The bug deputy plays an
important role in the Neutron community. As a large project, Neutron is
routinely fielding many bug reports. The bug deputy is responsible for
acting as a "first contact" for these bug reports and performing initial
screening/triaging. The bug deputy is expected to communicate with the
various Neutron teams when a bug has been triaged. In addition, the bug
deputy should be reporting "High" and "Critical" priority bugs.

To avoid burnout, and to give a chance to everyone to gain experience in
defect management, the Neutron bug deputy is a rotating role. The rotation
will be set on a period (typically one or two weeks) determined by the team
during the weekly Neutron IRC meeting and/or according to holidays. During
the Neutron IRC meeting we will expect a volunteer to step up for the period.
Members of the Neutron core team are invited to fill in the role,
however non-core Neutron contributors who are interested are also
encouraged to take up the role.

This contributor is going to be the bug deputy for the period, and he/she
will be asked to report to the team during the subsequent IRC meeting. The
PTL will also work with the team to assess that everyone gets his/her fair
share at fulfilling this duty. It is reasonable to expect some imbalance
from time to time, and the team will work together to resolve it to ensure
that everyone is 100% effective and well rounded in their role as
_custodian_ of Neutron quality. Should the duty load be too much in busy
times of the release, the PTL and the team will work together to assess
whether more than one deputy is necessary in a given period.

The presence of a bug deputy does not mean the rest of the team is simply off
the hook for the period, in fact the bug deputy will have to actively work
with the Lieutenants/Drivers, and these should help in getting the bug report
moving down the resolution pipeline.

During the period a member acts as bug deputy, he/she is expected to watch
bugs filed against the Neutron projects (as listed above) and do a first
screening to determine potential severity, tagging, logstash queries, other
affected projects, affected releases, etc.

From time to time bugs will be filed and auto-assigned by members of the
core team to get them to a swift resolution. Obviously, the deputy is exempt
from screening these.

Finally, the PTL will work with the deputy to produce a brief summary of the
issues of the week to be shared with the larger team during the weekly IRC
meeting and tracked in the meeting notes. If for some reason the deputy is not
going to attend the team meeting to report, the deputy should consider sending
a brief report to the openstack-discuss@ mailing list in advance of the meeting.


Getting Ready to Serve as the Neutron Bug Deputy
------------------------------------------------

If you are interested in serving as the Neutron bug deputy, there are several
steps you will need to follow in order to be prepared.

* Request to be added to the `neutron-bugs team in Launchpad <https://launchpad.net/%7Eneutron-bugs>`_.
  This request will be approved when you are assigned a bug deputy slot.
* Read this page in full.  Keep this document in mind at all times as it
  describes the duties of the bug deputy and how to triage bugs particularly
  around setting the importance and tags of bugs.
* Sign up for neutron bug emails from LaunchPad.

  * Navigate to the `LaunchPad Neutron bug list <https://bugs.launchpad.net/neutron>`_.
  * On the right hand side, click on "Subscribe to bug mail".
  * In the pop-up that is displayed, keep the recipient as "Yourself", and your
    subscription something useful like "Neutron Bugs".  You can choose either
    option for how much mail you get, but keep in mind that getting mail for
    all changes - while informative - will result in several dozen emails per
    day at least.
  * Do the same for the `LaunchPad python-neutronclient bug list <https://bugs.launchpad.net/python-neutronclient>`_.

* Configure the information you get from `LaunchPad <https://bugs.launchpad.net/neutron>`_
  to make visible additional information, especially the 'age' of the bugs. You
  accomplish that by clicking the little gear on the left hand side of the
  screen at the top of the bugs list.  This provides an overview of information
  for each bug on a single page.
* Optional: Set up your mail client to highlight bug email that indicates a new
  bug has been filed, since those are the ones you will be wanting to triage.
  Filter based on email from "@bugs.launchpad.net" with "[NEW]" in the subject
  line.
* Volunteer during the course of the Neutron team meeting, when volunteers to
  be bug deputy are requested (usually towards the beginning of the meeting).
* View your scheduled week on the `Neutron Meetings page <https://wiki.openstack.org/wiki/Network/Meetings#Bug_deputy>`_.
* During your shift, if it is feasible for your timezone, plan on attending the
  Neutron Drivers meeting.  That way if you have tagged any bugs as RFE, you
  can be present to discuss them.


Bug Deputy routines in your week
--------------------------------

* Scan 'New' bugs to triage.
  If it doesn't have enough info to triage, ask more info and
  mark it 'Incomplete'.
  If you could confirm it by yourself, mark it 'Confirmed'.
  Otherwise, find someone familiar with the topic and ask his/her help.

* Scan 'Incomplete' bugs to see if it got more info.
  If it was, make it back to 'New'.

* Repeat the above routines for bugs filed in your week at least.
  If you can, do the same for older bugs.

* Take a note of bugs you processed.
  At the end of your week, post a report on openstack-discuss mailing list.


Plugin and Driver Repositories
------------------------------

Many plugins and drivers have backend code that exists in another repository.
These repositories may have their own Launchpad projects for bugs.  The teams
working on the code in these repos assume full responsibility for bug handling
in those projects. For this reason, bugs whose solution would exist solely in
the plugin/driver repo should not have Neutron in the affected projects section.
However, you should add Neutron (Or any other project) to that list only if you
expect that a patch is needed to that repo in order to solve the bug.

It's also worth adding that some of these projects are part of the so
called Neutron `stadium <https://governance.openstack.org/tc/reference/projects/neutron.html#deliverables-and-tags>`_.
Because of that, their release is managed centrally by the Neutron
release team; requests for releases need to be funnelled and screened
properly before they can happen. Release request process is described
:ref:`here <guideline-releases>`.


.. _guidelines:

Bug Screening Best Practices
----------------------------

When screening bug reports, the first step for the bug deputy is to assess
how well written the bug report is, and whether there is enough information
for anyone else besides the bug submitter to reproduce the bug and come up
with a fix. There is plenty of information on the `OpenStack Bugs <https://docs.openstack.org/project-team-guide/bugs.html>`_
on how to write a good bug `report <https://wiki.openstack.org/wiki/BugFilingRecommendations>`_
and to learn how to tell a good bug report from a bad one. Should the bug
report not adhere to these best practices, the bug deputy's first step
would be to redirect the submitter to this section, invite him/her to supply
the missing information, and mark the bug report as 'Incomplete'. For future
submissions, the reporter can then use the template provided below to ensure
speedy triaging. Done often enough, this practice should (ideally) ensure that
in the long run, only 'good' bug reports are going to be filed.

Bug Report Template
~~~~~~~~~~~~~~~~~~~

The more information you provide, the higher the chance of speedy triaging and
resolution: identifying the problem is half the solution. To this aim, when
writing a bug report, please consider supplying the following details and
following these suggestions:

* Summary (Bug title): keep it small, possibly one line. If you cannot describe
  the issue in less than 100 characters, you are probably submitting more than
  one bug at once.
* Further information (Bug description): conversely from other bug trackers,
  Launchpad does not provide a structured way of submitting bug-related
  information, but everything goes in this section. Therefore, you are invited
  to break down the description in the following fields:

  * High level description: provide a brief sentence (a couple of lines) of
    what are you trying to accomplish, or would like to accomplish differently;
    the 'why' is important, but can be omitted if obvious (not to you of course).
  * Pre-conditions: what is the initial state of your system? Please consider
    enumerating resources available in the system, if useful in diagnosing
    the problem. Who are you? A regular user or a super-user? Are you
    describing service-to-service interaction?
  * Step-by-step reproduction steps: these can be actual neutron client
    commands or raw API requests; Grab the output if you think it is useful.
    Please, consider using `paste.o.o <http://paste.openstack.org>`_ for long
    outputs as Launchpad poorly format the description field, making the
    reading experience somewhat painful.
  * Expected output: what did you hope to see? How would you have expected the
    system to behave? A specific error/success code? The output in a specific
    format? Or more than a user was supposed to see, or less?
  * Actual output: did the system silently fail (in this case log traces are
    useful)? Did you get a different response from what you expected?
  * Version:

    * OpenStack version (Specific stable branch, or git hash if from trunk);
    * Linux distro, kernel. For a distro, it's also worth knowing specific
      versions of client and server, not just major release;
    * Relevant underlying processes such as openvswitch, iproute etc;
    * DevStack or other _deployment_ mechanism?

  * Environment: what services are you running (core services like DB and
    AMQP broker, as well as Nova/hypervisor if it matters), and which type
    of deployment (clustered servers); if you are running DevStack, is it a
    single node? Is it multi-node? Are you reporting an issue in your own
    environment or something you encountered in the OpenStack CI
    Infrastructure, aka the Gate?
  * Perceived severity: what would you consider the `importance <https://docs.openstack.org/project-team-guide/bugs.html#Importance>`_
    to be?

* Tags (Affected component): try to use the existing tags by relying on
  auto-completion. Please, refrain from creating new ones, if you need
  new "official" tags_, please reach out to the PTL. If you would like
  a fix to be backported, please add a backport-potential tag.
  This does not mean you are gonna get the backport, as the stable team needs
  to follow the `stable branch policy <http://docs.openstack.org/project-team-guide/stable-branches.html>`_
  for merging fixes to stable branches.
* Attachments: consider attaching logs, truncated log snippets are rarely
  useful. Be proactive, and consider attaching redacted configuration files
  if you can, as that will speed up the resolution process greatly.


Bug Triage Process
~~~~~~~~~~~~~~~~~~

The process of bug triaging consists of the following steps:

* Check if a bug was filed for a correct component (project). If not, either
  change the project or mark it as "Invalid".
* For bugs that affect documentation proceed like this. If documentation
  affects:

  * the ReST API, add the "api-ref" tag to the bug.
  * the OpenStack manuals, like the Networking Guide or the Configuration
    Reference, create a patch for the affected files in the documentation
    directory in this repository. For a layout of the how the documentation
    directory is structured see the `effective neutron guide
    <../effective_neutron.html>`_
  * developer documentation (devref), set the bug to "Confirmed" for
    the project Neutron, otherwise set it to "Invalid".

* Check if a similar bug was filed before. Rely on your memory if Launchpad
  is not clever enough to spot a duplicate upon submission.  You may also
  check already verified bugs for `Neutron <https://review.opendev.org/#/q/status:open+label:Verified-2+project:openstack/neutron>`_
  and `python-neutronclient <https://review.opendev.org/#/q/status:open+label:Verified-2+project:openstack/python-neutronclient>`_
  to see if the bug has been reported.  If so, mark it as a duplicate of the
  previous bug.
* Check if the bug meets the requirements of a good bug report, by checking
  that the guidelines_ are being followed. Omitted information is still
  acceptable if the issue is clear nonetheless; use your good judgement and
  your experience. Consult another core member/PTL if in doubt. If the bug
  report needs some love, mark the bug as 'Incomplete', point the submitter
  to this document and hope he/she turns around quickly with the missing
  information.

If the bug report is sound, move next:

* Revise tags as recommended by the submitter. Ensure they are 'official'
  tags. If the bug report talks about deprecating features or config
  variables, add a deprecation tag to the list.
* As deputy one is usually excused not to process RFE bugs which are the
  responsibility of the drivers team members.
* Depending on ease of reproduction (or if the issue can be spotted in the
  code), mark it as 'Confirmed'. If you are unable to assess/triage the
  issue because you do not have access to a repro environment, consider
  reaching out the :ref:`Lieutenant <core-review-hierarchy>`,
  go-to person for the affected component;
  he/she may be able to help: assign the bug to him/her for further
  screening. If the bug already has an assignee, check that a patch is
  in progress. Sometimes more than one patch is required to address an
  issue, make sure that there is at least one patch that 'Closes' the bug
  or document/question what it takes to mark the bug as fixed.
* If the bug indicates test or gate failure, look at the failures for that
  test over time using `OpenStack Health <http://status.openstack.org/openstack-health/#/>`_
  or `OpenStack Logstash <http://logstash.openstack.org/#/dashboard/file/logstash.json>`_.
  This can help to validate whether the bug identifies an issue that is
  occurring all of the time, some of the time, or only for the bug submitter.
* If the bug is the result of a misuse of the system, mark the bug either
  as 'Won't fix', or 'Opinion' if you are still on the fence and need
  other people's input.
* Assign the importance after reviewing the proposed severity. Bugs that
  obviously break core and widely used functionality should get assigned as
  "High" or "Critical" importance. The same applies to bugs that were filed
  for gate failures.
* Choose a milestone, if you can. Targeted bugs are especially important
  close to the end of the release.
* (Optional). Add comments explaining the issue and possible strategy of
  fixing/working around the bug. Also, as good as some are at adding all
  thoughts to bugs, it is still helpful to share the in-progress items
  that might not be captured in a bug description or during our weekly
  meeting. In order to provide some guidance and reduce ramp up time as
  we rotate, tagging bugs with 'needs-attention' can be useful to quickly
  identify what reports need further screening/eyes on.

Check for Bugs with the 'timeout-abandon' tag:

* Search for any bugs with the timeout abandon tag:
  `Timeout abandon <https://bugs.launchpad.net/neutron/+bugs?field.tag=timeout-abandon>`_.
  This tag indicates that the bug had a patch associated with it that was
  automatically abandoned after a timing out with negative feedback.
* For each bug with this tag, determine if the bug is still valid and update
  the status accordingly. For example, if another patch fixed the bug, ensure
  it's marked as 'Fix Released'. Or, if that was the only patch for the bug and
  it's still valid, mark it as 'Confirmed'.
* After ensuring the bug report is in the correct state, remove the
  'timeout-abandon' tag.

You are done! Iterate.


Bug Expiration Policy and Bug Squashing
---------------------------------------

More can be found at this `Launchpad page <https://help.launchpad.net/BugExpiry>`_.
In a nutshell, in order to make a bug report expire automatically, it needs to be
unassigned, untargeted, and marked as Incomplete.

The OpenStack community has had `Bug Days <https://wiki.openstack.org/wiki/BugDays>`_
but they have not been wildly successful. In order to keep the list of open bugs set
to a manageable number (more like <100+, rather than closer to 1000+), at the end of
each release (in feature freeze and/or during less busy times), the PTL with the
help of team will go through the list of open (namely new, opinion, in progress,
confirmed, triaged) bugs, and do a major sweep to have the Launchpad Janitor pick
them up. This gives 60 days grace period to reporters/assignees to come back and
revive the bug. Assuming that at regime, bugs are properly reported, acknowledged
and fix-proposed, losing unaddressed issues is not going to be a major issue,
but brief stats will be collected to assess how the team is doing over time.


.. _tags:

Tagging Bugs
------------

Launchpad's Bug Tracker allows you to create ad-hoc groups of bugs with tagging.

In the Neutron team, we have a list of agreed tags that we may apply to bugs
reported against various aspects of Neutron itself. The list of approved tags
used to be available on the `wiki <https://wiki.openstack.org/wiki/Bug_Tags#Neutron>`_,
however the section has been moved here, to improve collaborative editing, and
keep the information more current. By using a standard set of tags, each
explained on this page, we can avoid confusion. A bug report can have more than
one tag at any given time.

Proposing New Tags
~~~~~~~~~~~~~~~~~~

New tags, or changes in the meaning of existing tags (or deletion), are to be
proposed via patch to this section. After discussion, and approval, a member of
the bug team will create/delete the tag in Launchpad. Each tag covers an area
with an identified go-to contact or :ref:`Lieutenant <core-review-hierarchy>`,
who can provide further insight. Bug queries are provided below for convenience,
more will be added over time if needed.

+-------------------------------+-----------------------------------------+--------------------------+
| Tag                           | Description                             | Contact                  |
+===============================+=========================================+==========================+
| access-control_               | A bug affecting RBAC and policy.yaml    | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| api_                          | A bug affecting the API layer           | Akihiro Motoki           |
+-------------------------------+-----------------------------------------+--------------------------+
| api-ref_                      | A bug affecting the API reference       | Akihiro Motoki           |
+-------------------------------+-----------------------------------------+--------------------------+
| auto-allocated-topology_      | A bug affecting get-me-a-network        | N/A                      |
+-------------------------------+-----------------------------------------+--------------------------+
| baremetal_                    | A bug affecting Ironic support          | N/A                      |
+-------------------------------+-----------------------------------------+--------------------------+
| db_                           | A bug affecting the DB layer            | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| deprecation_                  | To track config/feature deprecations    | Neutron PTL/drivers      |
+-------------------------------+-----------------------------------------+--------------------------+
| dns_                          | A bug affecting DNS integration         | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| doc_                          | A bug affecting in-tree doc             | Akihiro Motoki           |
+-------------------------------+-----------------------------------------+--------------------------+
| fullstack_                    | A bug in the fullstack subtree          | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| functional-tests_             | A bug in the functional tests subtree   | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| gate-failure_                 | A bug affecting gate stability          | Slawek Kaplonski         |
+-------------------------------+-----------------------------------------+--------------------------+
| ipv6_                         | A bug affecting IPv6 support            | Brian Haley              |
+-------------------------------+-----------------------------------------+--------------------------+
| l2-pop_                       | A bug in L2 Population mech driver      | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| l3-bgp_                       | A bug affecting neutron-dynamic-routing | Tobias Urdin/            |
|                               |                                         | Jens Harbott             |
+-------------------------------+-----------------------------------------+--------------------------+
| l3-dvr-backlog_               | A bug affecting distributed routing     | Yulong Liu/              |
|                               |                                         | Brian Haley              |
+-------------------------------+-----------------------------------------+--------------------------+
| l3-ha_                        | A bug affecting L3 HA (vrrp)            | Brian Haley              |
+-------------------------------+-----------------------------------------+--------------------------+
| l3-ipam-dhcp_                 | A bug affecting L3/DHCP/metadata        | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| lib_                          | An issue affecting neutron-lib          | Neutron PTL              |
+-------------------------------+-----------------------------------------+--------------------------+
| linuxbridge_                  | A bug affecting ML2/linuxbridge         | N/A                      |
+-------------------------------+-----------------------------------------+--------------------------+
| loadimpact_                   | Performance penalty/improvements        | Miguel Lavalle/          |
|                               |                                         | Oleg Bondarev            |
+-------------------------------+-----------------------------------------+--------------------------+
| logging_                      | An issue with logging guidelines        | N/A                      |
+-------------------------------+-----------------------------------------+--------------------------+
| low-hanging-fruit_            | Starter bugs for new contributors       | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| metering_                     | A bug affecting the metering layer      | N/A                      |
+-------------------------------+-----------------------------------------+--------------------------+
| needs-attention_              | A bug that needs further screening      | PTL/Bug Deputy           |
+-------------------------------+-----------------------------------------+--------------------------+
| opnfv_                        | Reported by/affecting OPNFV initiative  | Drivers team             |
+-------------------------------+-----------------------------------------+--------------------------+
| ops_                          | Reported by or affecting operators      | Drivers Team             |
+-------------------------------+-----------------------------------------+--------------------------+
| oslo_                         | An interop/cross-project issue          | Bernard Cafarelli/       |
|                               |                                         | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| ovn_                          | A bug affecting ML2/OVN                 | Jakub Libosvar/          |
|                               |                                         | Lucas Alvares Gomes      |
+-------------------------------+-----------------------------------------+--------------------------+
| ovn-octavia-provider_         | A bug affecting OVN Octavia provider    | Brian Haley/             |
|                               | driver                                  | Flavio Fernandes         |
+-------------------------------+-----------------------------------------+--------------------------+
| ovs_                          | A bug affecting ML2/OVS                 | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| ovs-fw_                       | A bug affecting OVS firewall            | Miguel Lavalle           |
+-------------------------------+-----------------------------------------+--------------------------+
| ovsdb-lib_                    | A bug affecting OVSDB library           | Terry Wilson             |
+-------------------------------+-----------------------------------------+--------------------------+
| qos_                          | A bug affecting ML2/QoS                 | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| rfe_                          | Feature enhancements being screened     | Drivers Team             |
+-------------------------------+-----------------------------------------+--------------------------+
| rfe-confirmed_                | Confirmed feature enhancements          | Drivers Team             |
+-------------------------------+-----------------------------------------+--------------------------+
| rfe-triaged_                  | Triaged feature enhancements            | Drivers Team             |
+-------------------------------+-----------------------------------------+--------------------------+
| rfe-approved_                 | Approved feature enhancements           | Drivers Team             |
+-------------------------------+-----------------------------------------+--------------------------+
| rfe-postponed_                | Postponed feature enhancements          | Drivers Team             |
+-------------------------------+-----------------------------------------+--------------------------+
| sg-fw_                        | A bug affecting security groups         | Brian Haley              |
+-------------------------------+-----------------------------------------+--------------------------+
| sriov-pci-pt_                 | A bug affecting Sriov/PCI PassThrough   | Moshe Levi               |
+-------------------------------+-----------------------------------------+--------------------------+
| tempest_                      | A bug in tempest subtree tests          | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| troubleshooting_              | An issue affecting ease of debugging    | PTL/Drivers Team         |
+-------------------------------+-----------------------------------------+--------------------------+
| unittest_                     | A bug affecting the unit test subtree   | Rodolfo Alonso Hernandez |
+-------------------------------+-----------------------------------------+--------------------------+
| usability_                    | UX, interoperability, feature parity    | PTL/Drivers Team         |
+-------------------------------+-----------------------------------------+--------------------------+
| vpnaas_                       | A bug affecting neutron-vpnaas          | Dongcan Ye               |
+-------------------------------+-----------------------------------------+--------------------------+
| xxx-backport-potential_       | Cherry-pick request for stable team     | Bernard Cafarelli/       |
|                               |                                         | Brian Haley              |
+-------------------------------+-----------------------------------------+--------------------------+

.. _access-control:

Access Control
++++++++++++++

* `Access Control - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=access-control>`_
* `Access Control - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=access-control>`_

.. _api:

API
+++

* `API - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=api>`_
* `API - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=api>`_

.. _api-ref:

API Reference
+++++++++++++

* `API Reference - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=api-ref>`_
* `API Reference - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=api-ref>`_

.. _auto-allocated-topology:

Auto Allocated Topology
+++++++++++++++++++++++

* `Auto Allocated Topology - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=auto-allocated-topology>`_
* `Auto Allocated Topology - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=auto-allocated-topology>`_

.. _baremetal:

Baremetal
+++++++++

* `Baremetal - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=baremetal>`_
* `Baremetal - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=baremetal>`_

.. _db:

DB
++

* `DB - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=db>`_
* `DB - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=db>`_

.. _deprecation:

Deprecation
+++++++++++

* `Deprecation - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=deprecation>`_
* `DeprecationB - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=deprecation>`_


.. _dns:

DNS
+++

* `DNS - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=dns>`_
* `DNS - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=dns>`_

.. _doc:

DOC
+++

* `DOC - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=doc>`_
* `DOC - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=doc>`_

.. _fullstack:

Fullstack
+++++++++

* `Fullstack - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=fullstack>`_
* `Fullstack - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=fullstack>`_

.. _functional-tests:

Functional Tests
++++++++++++++++

* `Functional tests - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=functional-tests>`_
* `Functional tests - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=functional-tests>`_

.. _fwaas:

FWAAS
+++++

* `FWaaS - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=fwaas>`_
* `FWaaS - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=fwaas>`_

.. _gate-failure:

Gate Failure
++++++++++++

* `Gate failure - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=gate-failure>`_
* `Gate failure - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=gate-failure>`_

.. _ipv6:

IPV6
++++

* `IPv6 - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ipv6>`_
* `IPv6 - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=ipv6>`_

.. _l2-pop:

L2 Population
+++++++++++++

* `L2 Pop - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=l2-pop>`_
* `L2 Pop - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=l2-pop>`_

.. _l3-bgp:

L3 BGP
++++++

* `L3 BGP - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=l3-bgp>`_
* `L3 BGP - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=l3-bgp>`_

.. _l3-dvr-backlog:

L3 DVR Backlog
++++++++++++++

* `L3 DVR - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=l3-dvr-backlog>`_
* `L3 DVR - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=l3-dvr-backlog>`_

.. _l3-ha:

L3 HA
+++++

* `L3 HA - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=l3-ha>`_
* `L3 HA - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=l3-ha>`_

.. _l3-ipam-dhcp:

L3 IPAM DHCP
++++++++++++

* `L3 IPAM DHCP - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=l3-ipam-dhcp>`_
* `L3 IPAM DHCP - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=l3-ipam-dhcp>`_

.. _lib:

Lib
+++

* `Lib - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=lib>`_

.. _linuxbridge:

LinuxBridge
+++++++++++

* `LinuxBridge - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=linuxbridge>`_
* `LinuxBridge - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=linuxbridge>`_

.. _loadimpact:

Load Impact
+++++++++++

* `Load Impact - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=loadimpact>`_
* `Load Impact - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=loadimpact>`_

.. _logging:

Logging
+++++++

* `Logging - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=logging>`_
* `Logging - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=logging>`_

.. _low-hanging-fruit:

Low hanging fruit
+++++++++++++++++

* `Low hanging fruit - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=low-hanging-fruit>`_
* `Low hanging fruit - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=low-hanging-fruit>`_

.. _metering:

Metering
++++++++

* `Metering - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=metering>`_
* `Metering - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=metering>`_

.. _needs-attention:

Needs Attention
+++++++++++++++

* `Needs Attention - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=needs-attention>`_

.. _opnfv:

OPNFV
+++++

* `OPNFV - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=opnfv>`_

.. _ops:

Operators/Operations (ops)
++++++++++++++++++++++++++

* `Ops - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ops>`_

.. _oslo:

OSLO
++++

* `Oslo - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=oslo>`_
* `Oslo - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=oslo>`_

.. _ovn:

OVN
+++

* `OVN - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ovn>`_
* `OVN - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=ovn>`_

.. _ovn-octavia-provider:

OVN Octavia Provider driver
+++++++++++++++++++++++++++

* `OVN Octavia Provider driver - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ovn-octavia-provider>`_
* `OVN Octavia Provider driver - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=ovn-octavia-provider>`_

.. _ovs:

OVS
+++

* `OVS - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ovs>`_
* `OVS - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=ovs>`_

.. _ovs-fw:

OVS Firewall
++++++++++++

* `OVS Firewall - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ovs-fw>`_
* `OVS Firewall - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=ovs-fw>`_

.. _ovsdb-lib:

OVSDB Lib
+++++++++

* `OVSDB Lib - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=ovsdb-lib>`_
* `OVSDB Lib - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=ovsdb-lib>`_

.. _qos:

QoS
+++

* `QoS - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=qos>`_
* `QoS - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=qos>`_

.. _rfe:

RFE
+++

* `RFE - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe>`_
* `RFE - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=rfe>`_

.. _rfe-confirmed:

RFE-Confirmed
+++++++++++++

* `RFE-Confirmed - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe-confirmed>`_

.. _rfe-triaged:

RFE-Triaged
+++++++++++

* `RFE-Triaged - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe-triaged>`_

.. _rfe-approved:

RFE-Approved
++++++++++++

* `RFE-Approved - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe-approved>`_
* `RFE-Approved - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=rfe-approved>`_

.. _rfe-postponed:

RFE-Postponed
+++++++++++++

* `RFE-Postponed - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=rfe-postponed>`_
* `RFE-Postponed - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=rfe-postponed>`_

.. _sriov-pci-pt:

SRIOV-PCI PASSTHROUGH
+++++++++++++++++++++

* `SRIOV/PCI-PT - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=sriov-pci-pt>`_
* `SRIOV/PCI-PT - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=sriov-pci-pt>`_

.. _sg-fw:

SG-FW
+++++

* `Security groups - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=sg-fw>`_
* `Security groups - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=sg-fw>`_

.. _tempest:

Tempest
+++++++

* `Tempest - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=Tempest>`_
* `Tempest - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=Tempest>`_


.. _troubleshooting:

Troubleshooting
+++++++++++++++

* `Troubleshooting - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=Troubleshooting>`_
* `Troubleshooting - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=Troubleshooting>`_

.. _unittest:

Unit test
+++++++++

* `Unit test - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=unittest>`_
* `Unit test - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=unittest>`_

.. _usability:

Usability
+++++++++

* `UX - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=usability>`_
* `UX - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=usability>`_

.. _vpnaas:

VPNAAS
++++++

* `VPNaaS - All bugs <https://bugs.launchpad.net/neutron/+bugs?field.tag=vpnaas>`_
* `VPNaaS - In progress <https://bugs.launchpad.net/neutron/+bugs?field.status%3Alist=INPROGRESS&field.tag=vpnaas>`_

.. _xxx-backport-potential:

Backport/RC potential
+++++++++++++++++++++

List of all ``Backport/RC potential`` bugs for stable releases can be found on
launchpad. Pointer to Launchpad's page with list of such bugs for any stable
release can be built by using link:

https://bugs.launchpad.net/neutron/+bugs?field.tag={STABLE_BRANCH}-backport-potential

where ``STABLE_BRANCH`` is always name of one of the 3 latest releases.
