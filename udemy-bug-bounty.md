# Udemy bug bounty report 
Udemy bug bounty program is provided by [HackerOne.com](https://hackerone.com/udemy). 

## Policy
If you believe you have found a security vulnerability on the Udemy site, we encourage you to provide additional details right away. We will investigate all legitimate reports and do our best to fix these problems as quickly as possible, given the level of threat involved.

Udemy’s bounty program is designed to reward those who help us maintain a safe Udemy site for all of our users.

Here’s more information on our bounty program:

- You must provide all the details of the vulnerability up front before we consider possible rewards.
- The security bug must be original and previously unreported. Known vulnerabilities will not qualify for a reward.
- Udemy reserves the right to not give a bounty payment if we believe the actions of the reporter have endangered the security of Udemy’s end users.
- The issue must be resolved by our engineers before the reward is provided.
- Out of scope reports include the following:
    - No XSS reports temporarily - we are behind on fixing and analysing them.
    - Self-XSS, attacks that do not have the possibility of targeting other users.
    - Exploits that require significant social engineering.
    - Please do not submit any reports mentioning password reset links or cookie reuse. This is in progress.
    - SMTP, DMARC, etc. email records settings
    - Video streaming or downloading videos
    - All of the following subdomains are NOT in scope:
        - about, affiliate, blog, business, community, press, teach, learning, research, support, mi, helpdesk - or any additional word press sites not listed.

## Scope
- [Udemy.com](https://www.udemy.com/)

### Vulnerability Types
* Remote Shell / Command Injection
* Remote Code Execution
* SQL Injection (with output)
* Significant Authentication Bypass
* Local file Inclusion
* SQL Injection (blind)
* Insecure Direct Object References
* Server Side Request Forgery
* Stored Cross Site Scripting
* Other Cross Site Scripting

## 1. Remote Shell / Command Injection
Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application. 
Command injection attacks are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. 
In this attack, the attacker-supplied operating system commands are usually executed with the privileges of the vulnerable application. 
Command injection attacks are possible largely due to insufficient input validation.

This attack differs from Code Injection, in that code injection allows the attacker to add his own code that is then executed by the application. 
In Command Injection, the attacker extends the default functionality of the application, which execute system commands, without the necessity of injecting code. [1]

### Command Injection using DVWA
_"Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application that is damn vulnerable. 
Its main goals are to be an aid for security professionals to test their skills and tools in a legal environment, 
help web developers better understand the processes of securing web applications and aid teachers/students to teach/learn web application security in a class room environment."_[2]




### References
[1] Command Injection - OWASP. Command Injection - OWASP [online]. Texas, USA: OWASP Foundation, 2018 [quoted. 2019-04-13]. Availiable from: https://www.owasp.org/index.php/Command_Injection
[2] DVWA - Damn Vulnerable Web Application [online]. UK: DVWA, 2019 [quoted. 2019-04-13]. Availiable from: http://www.dvwa.co.uk/
