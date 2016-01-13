## Eventlog to Syslog Service for Windows ##

This program is written in C and provides a method of sending Windows Eventlog events to a syslog server. It works with the new Windows Events service found in Vista and Server 2008 and can be compiled for both 32 and 64-bit environments. Designed to keep up with very busy servers, it is fast, light, and efficient.
The program is designed to run as a windows service.

It is an adaption of Curtis Smith's Eventlog to Syslog service found at https://engineering.purdue.edu/ECN/Resources/Documents/UNIX/evtsys/
#### It contains the following improvements on Smith's utility: ####
**NOTE: Pre-4.5 Users. The 4.5 update changes how log hosts are configured. Please make sure your registry keys are consolidated into a single registry key with multiple hosts separated by a semicolon when upgrading, or just reinstall using the new format to specify your log hosts. Check the readme for full details.**

Update:
  * Added a new download file per user request. It's available in the downloads section as well as under the 4.4.3 tag's Executables folders. It is exactly the same as the 4.4.3 source code, built with a maximum message size of 4096.

Changes in v4.5.1:
  * Fixed issue where command-line hosts (-h) argument was not saved to the registry
  * Fixed an issue where the user might not be able to use the maximum of 6 log hosts

v4.5:
  * Addition of a Tag (-t) parameter allowing you to specify a custom parameter for the program field.
  * Addition of a parameter (-a) allowing use of an FQDN Hostname or IP address
  * IncludeOnly flag no longer used on Vista/Server 2k8
  * Allow use of XPath to specify events to forward on Vista/2008+
  * Removal of additional DLL, now a single file deployment
  * Removal of additional log host keys switching to instead use a single key

v4.4.3:
  * Improved performance in Server 2008 by implementing event subscriptions. Thanks to Martin for pointing me in the right direction.

v4.4.2:
  * Added support for custom tags from a server. Use the -t flag when installing (Thanks wired)
  * Added support for up to four log hosts simultaneously
  * Fix a bug that causes excessive errors when an event cannot be retrieved on Server 2008
  * Fix an issue not allowing a log level of 4 to be valid
  * Began support for configurable maximum log size. Not yet completed
  * Lightly tested TCP support has been implemented. Error checking and fault tolerance not yet finished. Documentation will be forthcoming for those who want to help test it