The Radware LBaaS driver uploads ADC workflows on-demand into vDirect. The ADC Workflows are composed from files which are located underneath this workflows directory.
The workflows directory is part of the Radware LBaaS driver code included in OpenStack.

Those ADC Workflows are instantiated and run in the vDirect Virtual Machine.
Radware's OpenStack LBaaS driver, uses vDirect REST API to activate those workflows and CRUD configuration in the Alteon device.

An ADC workflow is composed from:
1. A mandatory XML file called workflow.xml which defines the different states and the transition flow between states as well as "linking" to the actual code that can be done on each state.
2. ADC Configuration Template files with extension .vm which are using an extended apache velocity template engine syntax
3. ADC Configuration Groovy script file with extension .groovy

