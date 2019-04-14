# Dropbox bug bounty report 
Dropbox bug bounty program is provided by [HackerOne.com](https://hackerone.com/dropbox). 

## Policy
Keeping user information safe and secure is a top priority and a core company value for us at Dropbox. 
We welcome the contribution of external security researchers and look forward to awarding them for their invaluable contribution to the security of all Dropbox users.

To promote the discovery and reporting of vulnerabilities and increase user safety, we ask that you:
- Share the security issue with us in detail.
- Please be respectful of our existing applications. 
- Spamming forms through automated vulnerability scanners will not result in any bounty or award since those are explicitly out of scope;
- Give us a reasonable time to respond to the issue before making any information about it public.
- Do not access or modify our data or our users’ data, without explicit permission of the owner. Only interact with your own accounts or test accounts for security research purposes.
- Contact us immediately if you do inadvertently encounter user data. Do not view, alter, save, store, transfer, or otherwise access the data, and immediately purge any local information upon reporting the vulnerability to Dropbox.
- Act in good faith to avoid privacy violations, destruction of data, and interruption or degradation of our services (including denial of service). 
- Otherwise comply with all applicable laws.

## Scope
- [Dropbox.com](https://www.dropbox.com/)

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

### Command Injection explained in DVWA
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
