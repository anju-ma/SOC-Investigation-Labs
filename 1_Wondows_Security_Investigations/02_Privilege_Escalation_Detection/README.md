# Incident Summary
A suspicious privilege escalation activity was detected where a new user account was created and added to the local Administrators group. This action can allow an attacker to gain elevated privileges and maintain persistent access to the system.
# Log Source
Logs were analyzed from the Windows Security Event Log.
Relevant events:
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4688 | Process Creation |
| 4720 | User account created |
| 4732 | Member added to local Administrators group |
Logs were reviewed using Windows Event Viewer.
# Attack Scenario
A privilege escalation scenario was simulated on a Windows system.
Attack behavior:
* An attacker logged into the system using a normal user account.
* The attacker created a new user account.
* The attacker added the newly created account to the Administrators group.
Commands used during the attack simulation:
Copy code

net user hkuser Pass123! /add
net localgroup administrators hkuser /add
This technique is commonly used by attackers to gain administrative privileges and maintain persistence.
# Evidence (Log Snippets)
Successful Login
Event ID: 4624
Account Name: testuser
Logon Type: 3
User Account Created
Event ID: 4720
Account Name: hackeruser
Subject User Name: testuser
User Added to Administrators Group
Event ID: 4732
Member Name: hackeruser
Group Name: Administrators
# Timeline Reconstruction
| Time | Event |
|------|-------|
| 11:00 | Successful login detected (Event ID 4624) |
| 11:02 | New user account created (Event ID 4720) |
| 11:03 | User added to Administrators group (Event ID 4732) |
# Investigation Analysis
Investigation steps:
1. Filtered Windows Security logs for Event ID 4720 to identify newly created user accounts.
2. Verified which user performed the account creation.
3. Checked for Event ID 4732 to detect if the new user was added to privileged groups.
4. Correlated the events with a prior login event (4624).
The investigation confirmed that a user account was created and granted administrative privileges, indicating potential privilege escalation activity.
# Detection Logic
Privilege escalation can be detected by monitoring account creation and group membership changes.
Detection pattern:
Event ID 4720 (User created)
Followed by Event ID 4732 (Added to Administrators group)
Example detection rule:
Copy code

IF EventID = 4720
AND EventID = 4732
AND GroupName = "Administrators"
WITHIN 5 minutes
THEN trigger privilege escalation alert
Detection rules like this can be implemented in SIEM platforms such as Splunk or ELK.
# Attack Classification
Mapped to the MITRE ATT&CK Framework.
| Technique ID | Technique |
| T1078 | Valid Accounts |
| T1136 | Create Account |
Attackers may create new accounts and assign administrative privileges to maintain persistent access.
# Impact Analysis
If successful, privilege escalation may allow attackers to:
* Gain administrative control of the system
* Disable security controls
* Create persistence mechanisms
* Move laterally across the network
* Deploy malware or ransomware
Early detection is critical to prevent further compromise.
# Remediation Steps
Recommended security measures:
* Remove unauthorized accounts
* Review administrative group membership
* Reset passwords for affected accounts
* Implement least privilege access policies
* Enable security monitoring for account changes
# Conclusion
The investigation identified suspicious privilege escalation activity where a new user account was created and added to the Administrators group. Monitoring account creation and group membership changes can help security teams quickly detect unauthorized privilege escalation attempts.
