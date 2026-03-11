# Incident Summary
Multiple failed SSH login attempts were detected targeting a Linux user account from the same source IP address. After several authentication failures, a successful login occurred from the same IP. This pattern indicates a possible SSH brute force attack, where an attacker attempts multiple passwords until the correct one is discovered.
# Log Source
Logs were analyzed from the Linux authentication logs.
Relevant log file:
Copy code

/var/log/auth.log
System logs were reviewed using the following commands.
Example commands used during investigation:
Copy code

cat /var/log/auth.log
grep "Failed password" /var/log/auth.log
grep "Accepted password" /var/log/auth.log
Logs were analyzed using the Linux terminal.
# Attack Scenario
A brute force attack was simulated against a Linux SSH service.
Attack behavior:
* Multiple incorrect password attempts were made
* Each failed login generated a "Failed password" log entry
* After several attempts, the correct password was used
* The system logged "Accepted password", indicating successful authentication
This behavior is typical of SSH brute force attacks targeting weak passwords.
# Evidence (Log Snippets)
Failed Login Attempts
Example log entry:
Copy code

Failed password for testuser from 192.168.56.101 port 54321 ssh2
This indicates that a login attempt failed due to an incorrect password.
Successful Login
Example log entry:
Copy code

Accepted password for testuser from 192.168.56.101 port 54321 ssh2
This confirms that authentication was successful after several failed attempts.
# Timeline Reconstruction
| Time | Event |
|------|-------|
| 12:01 | Multiple failed SSH login attempts |
| 12:02 | Continued authentication failures | 
| 12:03 | Successful SSH login detected |
# Investigation Analysis
Investigation steps:
* Reviewed /var/log/auth.log for authentication activity
* Filtered logs containing Failed password
* Identified repeated login attempts targeting the same user
* Observed the source IP generating the attempts
* Checked for Accepted password entries after the failures
* Confirmed that the successful login originated from the same IP address
This pattern indicates a brute force authentication attack.
# Detection Logic
SSH brute force attacks can be detected by monitoring repeated authentication failures.
Detection pattern:
* Multiple Failed password attempts
* Same username
* Same source IP
Followed by Accepted password
Example detection logic:
Copy code

IF failed_ssh_logins > 5 within 2 minutes
AND same username
AND same source IP
THEN trigger SSH brute force alert
This detection logic can be implemented in SIEM platforms such as:
Splunk
Elastic Stack
# Attack Classification
Mapped to the **MITRE ATT&CK framework.
| Technique ID | Technique |
|--------------|-----------|
| T1110 | Brute Force |

Attackers attempt to guess passwords repeatedly to gain unauthorized access.
# Impact Analysis
If successful, an SSH brute force attack may allow attackers to:
* Gain unauthorized system access
* Execute commands on the server
* Install backdoors
* Move laterally across the network
* Exfiltrate sensitive data
Early detection helps prevent further compromise.
# Remediation Steps
Recommended security measures:
* Block the attacking IP address
* Disable password-based SSH authentication
* Implement SSH key-based authentication
* Enable account lockout policies
* Deploy intrusion prevention tools such as Fail2Ban
# Conclusion
The investigation identified a brute force attack against the SSH service by correlating multiple failed login attempts with a successful authentication from the same IP address. Monitoring authentication logs and implementing automated detection rules can help security teams quickly detect and respond to such attacks.

