# Posh-Stig
The purpose of this project is to create a PowerShell module that will allow quick evaluation and remediation of DISA STIGs.

Currently the idea is that each STIG will have its own 'Get' and 'Set' functions that will check settings or change settings. Out-StigCkl will be utilized to process all the settings into a .ckl file that can be viewed in STIG Viewer. The expected input for this function is an array of custom PSObjects, possibly implement a class for this and the vulnerabilities. A single object will represent a single .ckl. The expected format is below:

$Obj{

  [string]HostName;
  
  [string]IPAddress;
  
  [string]MACAddress;
  
  [string]FQDN;
  
  [string]Role;
  
  [string]ObjectType;
  
  [PSObject[]]Vulnerabilities
  
}

The vulnerabilities will be custom PSObjects each representing a single vulnerability in the STIG. The expected format is below:

$Vuln{

  [string]StigID;
  
  [string]Finding;
  
  [string]Status;
  
  [string]Comments
  
}

The StigID should be in the format of 'V-XXXXXX' and the valid values for Status are: 'Not_Reviewed', 'NotAFinding', 'Open', 'Not_Applicable'.

Long-term goal is to add a GUI to this and make it easy to modify site specific settings for vulnerabilities. This includes the Status, Findings, and Comments.

More to come at a later date.
