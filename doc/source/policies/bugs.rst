Neutron Bugs
============

Neutron maintains all of it's bugs in `Launchpad <https://bugs.launchpad.net/neutron>`_. All of
the current open Neutron bugs can be found in that link.

Neutron Bug Czar
----------------
Neutron maintains the notion of a "bug czar." The bug czar plays an important role in the Neutron
community. As a large project, Neutron is routinely fielding many bug reports. The bug czar is
responsible for acting as a "first contact" for these bug reports and performing initial
triaging. The bug czar is expected to communicate with the various Neutron teams when a bug has
been triaged. In addition, the bug czar should be reporting "High" and "Critical" priority bugs
to both the PTL and the core reviewer team during each weekly Neutron meeting.

The current Neutron bug czar is Kyle Mestery (IRC nick mestery).

Plugin and Driver Repositories
------------------------------

Many plugins and drivers have backend code that exists in another repository.
These repositories have their own launchpad projects for bugs.  The teams
working on the code in these repos assume full responsibility for bug handling
in those projects.

Bug Triage Process
------------------

The process of bug triaging consists of the following steps:

1. Check if a bug was filed for a correct component (project). If not, either change the project
   or mark it as "Invalid".
2. Add appropriate tags. Even if the bug is not valid or is a duplicate of another one, it still
   may help bug submitters and corresponding sub-teams.
3. Check if a similar bug was filed before. If so, mark it as a duplicate of the previous bug.
4. Check if the bug description is consistent, e.g. it has enough information for developers to
   reproduce it. If it's not consistent, ask submitter to provide more info and mark a bug as
   "Incomplete".
5. Depending on ease of reproduction (or if the issue can be spotted in the code), mark it as
   "Confirmed".
6. Assign the importance. Bugs that obviously break core and widely used functionality should get
   assigned as "High" or "Critical" importance. The same applies to bugs that were filed for gate
   failures.
7. (Optional). Add comments explaining the issue and possible strategy of fixing/working around
   the bug.
