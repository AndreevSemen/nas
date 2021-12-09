#!/bin/bash

nmcli radio wifi on
nmcli dev status
nmcli dev wifi list

read -p "Enter wi-Fi SSID: " SSID
read -s -p "Enter password: " PASSWD
echo

nmcli dev wifi connect "$SSID" password "$PASSWD"
