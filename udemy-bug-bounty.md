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
help web developers better understand the processes of securing web applications and aid teachers/students to teach/learn web application security in a class room environment."_ [2]

The purpose of the command injection attack is to inject and execute commands specified by the attacker in the vulnerable application. 
In situation like this, the application, which executes unwanted system commands, is like a pseudo system shell, and the attacker may use it as any authorized system user. 
However, commands are executed with the same privileges and environment as the web service has.
Command injection attacks are possible in most cases because of lack of correct input data validation, which can be manipulated by the attacker (forms, cookies, HTTP headers etc.).
The syntax and commands may differ between the Operating Systems (OS), such as Linux and Windows, depending on their desired actions.
This attack may also be called "Remote Command Execution (RCE)".

#### Low level security Command Injection
This allows for direct input into one of many PHP functions that will execute commands on the OS. 
It is possible to escape out of the designed command and executed unintentional actions.
This can be done by adding on to the request, "once the command has executed successfully, run this command". 

##### Low level security Command Injection vulnerable application
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```

#### Medium level security Command Injection
The developer has read up on some of the issues with command injection, and placed in various pattern patching to filter the input. However, this isn't enough.
Various other system syntaxes can be used to break out of the desired command.

##### Medium level security Command Injection vulnerable application
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```

#### High level security Command Injection 
In the high level, the developer goes back to the drawing board and puts in even more pattern to match. But even this isn't enough.
The developer has either made a slight typo with the filters and believes a certain PHP command will save them from this mistake.

##### High level security Command Injection vulnerable application
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = trim($_REQUEST[ 'ip' ]);

    // Set blacklist
    $substitutions = array(
        '&'  => '',
        ';'  => '',
        '| ' => '',
        '-'  => '',
        '$'  => '',
        '('  => '',
        ')'  => '',
        '`'  => '',
        '||' => '',
    );

    // Remove any of the charactars in the array (blacklist).
    $target = str_replace( array_keys( $substitutions ), $substitutions, $target );

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```

#### Impossible level security Command Injection
In the impossible level, the challenge has been re-written, only to allow a very stricted input. 
If this doesn't match and doesn't produce a certain result, it will not be allowed to execute. 
Rather than "black listing" filtering (allowing any input and removing unwanted), this uses "white listing" (only allow certain values).

##### Impossible level security Command Injection vulnerable application
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $target = $_REQUEST[ 'ip' ];
    $target = stripslashes( $target );

    // Split the IP into 4 octects
    $octet = explode( ".", $target );

    // Check IF each octet is an integer
    if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
        // If all 4 octets are int's put the IP back together.
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];

        // Determine OS and execute the ping command.
        if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
            // Windows
            $cmd = shell_exec( 'ping  ' . $target );
        }
        else {
            // *nix
            $cmd = shell_exec( 'ping  -c 4 ' . $target );
        }

        // Feedback for the end user
        echo "<pre>{$cmd}</pre>";
    }
    else {
        // Ops. Let the user name theres a mistake
        echo '<pre>ERROR: You have entered an invalid IP.</pre>';
    }
}

// Generate Anti-CSRF token
generateSessionToken();

?> 
```

### References
- [1] Command Injection - OWASP. Command Injection - OWASP [online]. Texas, USA: OWASP Foundation, 2018 [quoted. 2019-04-13]. Availiable from: https://www.owasp.org/index.php/Command_Injection
- [2] DVWA - Damn Vulnerable Web Application [online]. UK: DVWA, 2019 [quoted. 2019-04-13]. Availiable from: http://www.dvwa.co.uk/
