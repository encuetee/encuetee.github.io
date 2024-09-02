---
title: 2023 ImaginaryCTF - idoriot revenge
date: 2023-07-23 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_imaginaryCTF
  - Web Exploitation
  - Authentication vulnerabilities
---

## Overview

* Points: 100

## Description

> The idiot who made it, made it so bad that the first version was super easy. It was changed to fix it.

## Analization

When registering, this code shows up

```php
<?php

session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Check if session is expired
if (time() > $_SESSION['expires']) {
    header("Location: logout.php");
    exit();
}

// Display user ID on landing page
echo "Welcome, User ID: " . urlencode($_SESSION['user_id']);

// Get the user for admin
$db = new PDO('sqlite:memory:');
$admin = $db->query('SELECT * FROM users WHERE username = "admin" LIMIT 1')->fetch();

// Check user_id
if (isset($_GET['user_id'])) {
    $user_id = (int) $_GET['user_id'];
    // Check if the user is admin
    if ($user_id == "php" && preg_match("/".$admin['username']."/", $_SESSION['username'])) {
        // Read the flag from flag.txt
        $flag = file_get_contents('/flag.txt');
        echo "<h1>Flag</h1>";
        echo "<p>$flag</p>";
    }
}

// Display the source code for this file
echo "<h1>Source Code</h1>";
highlight_file(__FILE__);
?>
```

Look at the condition

```php
if ($user_id == "php" && preg_match("/".$admin['username']."/", $_SESSION['username']))
```

The comparision of the ```user_id``` is not strict, so we could easily change the ```user_id``` to "php" to bypass.

The second condition, because username ```"admin"``` had ben registed, so the username ```"adminadmin"``` can be used (amazing!)

## Solution

Register the site with ```username = "adminadmin"```, and random password. Then change the ```user_id``` in the url to "php", then the flag will show up

The flag is

```
ictf{this_ch4lleng3_creator_1s_really_an_idoriot}
```