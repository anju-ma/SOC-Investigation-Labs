# Incident Summary
Multiple failed login attempts (Event ID 4625) were observed targeting the user account "testuser" from the same source IP address. Shortly after the failed attempts, a successful login (Event ID 4624) occurred from the same IP. This activity indicates a potential brute force authentication attack.
# Log Source
Logs were analyzed from the Windows Security Event Log.

Relevant events:
| Event ID | Description |
|----------|-------------|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |

Logs were reviewed using Windows Event Viewer.
# Attack Scenario
A brute force attack was simulated against a Windows user account.

Attack behavior:
* Multiple incorrect password attempts were generated.
* Each failed login produced Event ID 4625.
* After several attempts, the correct password was used, generating Event ID 4624.

This behavior is typical of password-guessing attacks.
# Evidence (Log Snippets)
Failed login
-------------------
| TargetUserName: TestUser |
| LogonType: 3 |
| FailureReason: Unknown user name or bad password |
| SoureNetworkAddress: 10.48.190.14 |

Successful login
--------------------
| Account Name: TestUser |
| Logon Type: 3 |
| Source Network Address: 10.48.190.14 |

# Timeline Reconstruction
| Time | Event |
|------|-------|
| 3:57 | Multiple failed login attempts |
| 3:58 | Continued authentication failures from same IP |
| 3.59 | Successful login detected (Event ID 4624) |
# Investigation Analysis
* Filtered Windows Security logs for Event ID 4625.
* Observed repeated failed login attempts targeting the same user.
* Identified the source IP address generating these attempts.
* Checked for Event ID 4624 after the failed attempts.
* Confirmed the successful login came from the same IP.
This pattern indicates a brute force authentication attempt.
# Detection Logic
Brute force attacks can be detected by monitoring abnormal authentication activity.
Detection pattern:
Multiple Event ID 4625
Same username
Same source IP
Followed by Event ID 4624
Example detection rule (SIEM):
IF failed_logins > 5 within 2 minutes
AND same username
AND same source IP
THEN trigger brute force alert
# Attack Classification
Mapped to the framework.
| Technique ID | Technique |
|--------------|-----------|
| T1110 | Brute Force |

Adversaries attempt to guess passwords repeatedly to gain unauthorized access to user accounts.
# Impact Analysis
If successful, a brute force attack may allow attackers to:
* Gain unauthorized access to user accounts
* Escalate privileges if the account has administrative rights
* Move laterally within the network
* Deploy malware or maintain persistence
Early detection is critical to prevent further compromise.

# Remediation Steps
Recommended security measures:
* Block the attacking IP address
* Temporarily disable the compromised account
* Force password reset
* Enable Multi-Factor Authentication (MFA)
* Implement account lockout policies

# Conclusion
The investigation identified a brute force authentication attack by correlating multiple failed login attempts with a successful login from the same source IP address. Monitoring authentication logs and implementing automated detection rules can help security teams quickly detect and respond to credential-based attacks.
