---
title: 2023 ImaginaryCTF - perfectpicture
date: 2023-07-23 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_imaginaryCTF
  - Web Exploitation
  - File upload vulnerabilities
---

## Overview

* Points: 100

## Description

> Someone seems awful particular about where their pixels go...

### Attached

[perfect_picture.zip](https://github.com/encuetee/CTF-writeups/blob/main/2023/2023_imaginaryctf/attached/perfect_picture.zip)

## Analyzation

By [xhacka](https://xhacka.github.io/posts/writeup/2023/07/23/Perfect-Picture/).

Only PNG files are allowed
```python
app.config['ALLOWED_EXTENSIONS'] = {'png'}
```

And there are some checks

```python
def check(uploaded_image):
    with open('flag.txt', 'r') as f:
        flag = f.read()
    with Image.open(app.config['UPLOAD_FOLDER'] + uploaded_image) as image:
        w, h = image.size
        if w != 690 or h != 420:
            return 0
        if image.getpixel((412, 309)) != (52, 146, 235, 123):
            return 0
        if image.getpixel((12, 209)) != (42, 16, 125, 231):
            return 0
        if image.getpixel((264, 143)) != (122, 136, 25, 213):
            return 0

    with exiftool.ExifToolHelper() as et:
        metadata = et.get_metadata(app.config['UPLOAD_FOLDER'] + uploaded_image)[0]
        try:
            if metadata["PNG:Description"] != "jctf{not_the_flag}":
                return 0
            if metadata["PNG:Title"] != "kool_pic":
                return 0
            if metadata["PNG:Author"] != "anon":
                return 0
        except:
            return 0
    return flag

```

## Solution

This is the script from [xhacka](https://xhacka.github.io/posts/writeup/2023/07/23/Perfect-Picture/)

```python
from PIL import Image
from PIL.PngImagePlugin import PngInfo

image = Image.new("RGBA", (690, 420), "white")
image.putpixel((412, 309), (52, 146, 235, 123))
image.putpixel((12, 209), (42, 16, 125, 231))
image.putpixel((264, 143), (122, 136, 25, 213))

metadata = PngInfo()
metadata.add_text("Description", "jctf{not_the_flag}")
metadata.add_text("Title", "kool_pic")
metadata.add_text("Author", "anon")

image.save('letmein.png', pnginfo=metadata)
image.close()

```

Submit and get the flag

```
ictf{7ruly_th3_n3x7_p1c4ss0_753433}
```

Another solution from [f0rk3b0mb](https://f0rk3b0mb.github.io/p/imaginaryctf2023/#perfect-picture)

```python

from PIL import Image

def create_and_modify_image():
    # Step 1: Create the Image
    width, height = 690, 420
    image = Image.new("RGBA", (width, height), (255, 255, 255, 0))

    # Step 2: Modify Pixel Colors
    image.putpixel((412, 309), (52, 146, 235, 123))
    image.putpixel((12, 209), (42, 16, 125, 231))
    image.putpixel((264, 143), (122, 136, 25, 213))
    # Step 3: Save the Image
    image.save("created_image.png")


if __name__ == "__main__":
    create_and_modify_image()

```

and modifies the information of picture by [exiftool](https://exiftool.org/)

```sh
exiftool -PNG:Description="jctf{not_the_flag}" -PNG:Title="kool_pic" -PNG:Author="anon" created_image.png
```

The first solution is faster!