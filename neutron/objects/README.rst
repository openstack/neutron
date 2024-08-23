===============
Neutron Objects
===============


Directory
=========

This directory is designed to contain all modules which have objects
definitions shipped with core Neutron. The files and directories located inside
of this directory should follow the guidelines below.


Structure
---------

The Neutron objects tree should have the following structure:

* The expected directory structure is flat, except for the ML2 plugins. All ML2
  plugin objects should fall under the plugins subdirectory
  (i.e. plugins/ml2/gre_allocation).
* Module names should use singular forms for nouns
  (network.py, not networks.py).

