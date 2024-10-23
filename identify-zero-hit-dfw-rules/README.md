# Identify rules with zero hits
This script identifies all rules within a targeted NSX Manager which have 0 rule hits. It prints the rule ID and policy ID to the console.

It uses the Policy API via the NSX Manager to gather and identify this information.

NSX Manager FQDN, Username and Password need to be populated in the script.