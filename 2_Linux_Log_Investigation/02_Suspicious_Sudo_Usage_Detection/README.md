# Incident Summary
Suspicious privileged command execution was detected on a Linux system where a standard user account executed commands using sudo to gain elevated privileges. Such behavior may indicate privilege escalation attempts or unauthorized administrative activity performed by an attacker after gaining initial access.
# Log Source
Logs were analyzed from the Linux authentication logs.
Relevant log file:
Copy code

/var/log/auth.log
System logs were reviewed using the following commands.
Example commands used during investigation:
Copy code

cat /var/log/auth.log
grep "sudo" /var/log/auth.log
grep "COMMAND=" /var/log/auth.log
Logs were analyzed using the Linux terminal.
# Attack Scenario
Suspicious sudo activity was simulated on a Linux system.
Attack behavior:
* A normal user logged into the system
* The user executed privileged commands using sudo
* Commands were executed with root privileges
* The activity was recorded in the authentication logs
Example commands used during attack simulation:
Copy code

sudo whoami
sudo cat /etc/shadow
sudo useradd hacker
This behavior is commonly observed when attackers attempt to escalate privileges or perform administrative actions after gaining access to a system.
# Evidence (Log Snippets)
Sudo Command Execution
Example log entry:
Copy code

testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/usr/bin/whoami
This indicates that user testuser executed a command with root privileges using sudo.
Suspicious Administrative Command
Example log entry:
Copy code

testuser : TTY=pts/0 ; PWD=/home/testuser ; USER=root ; COMMAND=/usr/sbin/useradd hacker
This shows that a new user account was created using sudo privileges.
# Timeline Reconstruction
| Time | Event |
|------|-------|
| 13:01 | User login detected |
| 13:03 | User executed sudo command |
| 13:05 | Administrative command executed using sudo |
# Investigation Analysis
Investigation steps:
* Reviewed /var/log/auth.log for authentication activity
* Filtered logs containing sudo command execution
* Identified which user executed privileged commands
* Examined commands executed with root privileges
* Checked for suspicious administrative activities such as user creation or sensitive file access
The investigation confirmed that a user executed commands with elevated privileges using sudo, which may indicate potential privilege escalation or misuse of administrative privileges.
# Detection Logic
Suspicious sudo usage can be detected by monitoring privileged command execution.
Detection pattern:
* sudo command execution
* normal user executing privileged commands
* administrative actions such as user creation or password modification
Example detection logic:
Copy code

IF sudo command executed
AND command contains useradd OR passwd OR /etc/shadow
THEN trigger suspicious sudo activity alert
This detection logic can be implemented in SIEM platforms such as:
Splunk
Elastic Stack
# Attack Classification
Mapped to the MITRE ATT&CK framework.
| Technique ID | Technique |
|--------------|-----------|
| T1548 | Abuse Elevation Control Mechanism |

Attackers may abuse privilege escalation mechanisms like sudo to execute commands with elevated privileges.
# Impact Analysis
If suspicious sudo usage is malicious, attackers may be able to:
* gain root privileges
* modify system configurations
* create backdoor accounts
* disable security controls
* install malware
* maintain persistent access
Monitoring sudo activity is critical to detect privilege escalation attempts.
# Remediation Steps
Recommended security measures:
* restrict sudo privileges to trusted users
* implement least privilege access policies
* regularly audit sudo logs
* monitor privileged command execution
* use centralized logging and SIEM monitoring
# Conclusion
The investigation identified suspicious privileged command execution using sudo. Monitoring authentication logs and analyzing sudo activity helps security teams detect unauthorized administrative actions and potential privilege escalation attempts.
