# USB/IP

I run USB/IP on a Raspberry Pi to funnel my Zigbee antenna to Home Assistant running in the basement.
Steps to get things set-up:

1. I installed `vlan` and `usbip` on the Raspberry Pi and enabled the required `modules`.
1. I set-up the correct VLAN with `nmtui`.
1. I added the `usbip` services to `/etc/systemd/system/` and enabled them for `skyconnect.conf` for `skyconnect.conf` for `skyconnect.conf` for `skyconnect.conf`.
1. On Home Assistant, I installed a [USB/IP add-on](https://github.com/cryptedx/ha-usbip-client) and imported the USB stick.

The setup for USB/IP is well documented in the [Arch Linux Wiki](https://wiki.archlinux.org/title/USB/IP).
