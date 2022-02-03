The Get-LateralMovement.ps1 script is based on the SANS Hunt Evil ("blue") poster and was created to process relevant event log, registry, and file system artifacts for evidence of lateral movement.

The script accepts a mounted drive or full path to an evidence source.  This source can be a drive image mounted with Arsenal Image Mounter, a mounted VHDX file created by KAPE, or the local C: drive of the running system.

The output path must be supplied on the command line and the script uses Eric Zimmerman's Tools to create CSV output that can be parsed or reviewed for evidence of lateral movement.  The path to the tools directory is specified by the $Tools variable in the script and must be changed to match the specific path on your analysis machine or USB device.
