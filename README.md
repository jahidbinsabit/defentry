# Defentry — Smart Security & Login Protection

Device-based login verification for WordPress. When someone logs in from a new device, Defentry blocks the screen with a red verification overlay, sounds a siren, and alerts all other logged-in admins in real time — until the Siren Stop Password is entered.

## Features

- **New-device verification overlay** — full-screen red prompt requiring the Siren Stop Password
- **Siren alerts** — audible alarm on the new device and on every other logged-in admin's browser
- **Realtime broadcast** — other admins see a blinking warning banner within ~25 seconds, no page reload needed
- **Trusted device management** — per-user device lists, one-click remove, danger-zone reset
- **IP attempt limiting** — 3 wrong passwords → IP blocked for 1 hour (REMOTE_ADDR only, spoof-proof)
- **Master Admin control** — only the Master Admin sees settings; secondary admins stay protected but can't change anything
- **Instant IP block** — block a suspicious IP straight from the alert banner
- **Email alerts** — other admins get notified of new device logins

## Installation

1. Upload the plugin folder to `/wp-content/plugins/` or install the ZIP via **Plugins → Add New → Upload**.
2. Activate **Defentry**.
3. A setup wizard will ask you to choose the **Master Admin**, set the **Siren Stop Password**, and turn protection **ON**.

## Requirements

- WordPress 5.0+
- PHP 7.4+

## License

GPLv2 or later — same as WordPress.

## Author

**Md Jahid Bin Sabit** — WordPress Security Specialist ([jbsabit.com](https://jbsabit.com))

Also on WordPress.org: [wordpress.org/plugins/defentry](https://wordpress.org/plugins/defentry/)
