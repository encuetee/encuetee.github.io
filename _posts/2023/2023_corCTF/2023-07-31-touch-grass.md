---
title: 2023 corCTF - touch-grass
date: 2023-07-31 00:00:00 +0700
categories:
  - Write-ups
tags:
  - 2023_corCTF
  - Miscellaneous
---

## Overview

* 89 solves / 133 points
* authors: Strellic, FizzBuzz101, 0x5a

## Description

> Vitamin D deficiency and complications from a sedentary lifestyle are plaguing the CTF community.
>
> To help change this, the esteemed CoR tribunal has decided that touching grass in sunlight is a vital part of this CTF experience.
>
> Trying to trick this system will result in your team being placed on a hall of SHAME - the entire world will know that you don't touch grass!
>
> [https://touch-grass.be.ax/](https://touch-grass.be.ax/)

## Analyzation

Get into the url, the authors said
```
to get your flag, your image must contain all of the following:

1. grass (obviously) (dirt or plants are also fine)
2. a hand (preferably touching the grass)
3. and the following code: abcdefgh, written on a piece of paper (please write legibly and clearly)
4. please submit the image with the code upright and very visible so it can be read correctly

please do not forget the above code, we need it to make sure that you didn't photoshop or edit the image!
```

## Solution

Do exactly what they said, post an image!

The flag is
```
corctf{i_hope_you_d1dnt_have_a_gr4ss_allergy}
```