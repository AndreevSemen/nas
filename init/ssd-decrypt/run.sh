#!/bin/bash

cryptsetup luksOpen /dev/sda ssd
mount /dev/mapper/ssd /mnt/ssd
