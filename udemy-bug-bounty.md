# Udemy bug bounty report 

## Policy
If you believe you have found a security vulnerability on the Udemy site, we encourage you to provide additional details right away. We will investigate all legitimate reports and do our best to fix these problems as quickly as possible, given the level of threat involved.

Udemy’s bounty program is designed to reward those who help us maintain a safe Udemy site for all of our users.

Here’s more information on our bounty program:

- You must provide all the details of the vulnerability up front before we consider possible rewards
- The security bug must be original and previously unreported. Known vulnerabilities will not qualify for a reward
- Udemy reserves the right to not give a bounty payment if we believe the actions of the reporter have endangered the security of Udemy’s end users.
- The issue must be resolved by our engineers before the reward is provided
- Out of scope reports include the following:
    - No XSS reports temporarily - we are behind on fixing and analysing them
    - Self-XSS, attacks that do not have the possibility of targeting other users
    - Exploits that require significant social engineering
    - Please do not submit any reports mentioning password reset links or cookie reuse. This is in progress.
    - SMTP, DMARC, etc. email records settings
    - Video streaming or downloading videos
    -All of the following subdomains are NOT in scope:
        - about, affiliate, blog, business, community, press, teach, learning, research, support, mi, helpdesk - or any additional word press sites not listed.

### Vulnerability Types
* Remote Shell / Command Execution
* Remote Code Execution
* SQL Injection (with output)
* Significant Authentication Bypass
* Local file Inclusion
* SQL Injection (blind)
* Insecure Direct Object References
* Server Side Request Forgery
* Stored Cross Site Scripting
* Other Cross Site Scripting

