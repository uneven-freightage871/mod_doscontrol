# Apache2.4 mod_doscontrol

Apache request abuse detector for DoS detection, spam-flood monitoring, suspicious traffic analysis, IP and User-Agent whitelisting, incident logging, external script triggering, and automated response handling.

**Version**: v1.0.0 [2026.0328]

---

## About

`mod_doscontrol` is an Apache HTTP Server module built to detect abusive request patterns, suspicious traffic, spam-like floods, crawler pressure, and early-stage DoS behavior.

It is a detection-first module. It watches request rates and patterns, then reacts according to configuration. When suspicious activity is detected, `mod_doscontrol` can return a configured HTTP response, delay the response, write logs, create incident cache markers, send email notifications, or run an external command or script.

The project was built as a **substantial refactor and rework of `mod_evasive`**, using that codebase as the practical starting point and reshaping it into a different implementation with broader configuration and response options.

This project is useful when you want to detect abuse, inform both sides through response and notification handling, and trigger external scripts or programs for further action.

### Origin and authorship

`mod_evasive` provided the original practical base and idea. That work is associated with:

- Jonathan Zdziarski
- Copyright (c) 2005
- GPLv2 "or later"
- Available [here](https://github.com/jzdziarski/mod_evasive/) 

`mod_doscontrol` is a separate refactored implementation by:

- Kamil "BuriXon" Burek
- Copyright (c) 2026
- GPLv3 "or later"

### Scope

This module is meant for:

- DoS and DDoS detection
- spam and flood detection
- bot abuse detection
- brute-force style request monitoring
- noisy crawler control
- incident logging and automation
- external response triggering

### Platform note

This project currently targets Apache 2.4 HTTP Server builds in the usual Unix/Linux server environment.

> [!NOTE]
> It does not currently work on Termux. I am a big fan of Termux, and I will keep working toward future compatibility.

---

## Features

- Apache module for abuse and DoS detection
- Per-page request counting
- Per-site request counting
- Configurable detection windows
- Configurable blocking period
- Configurable response code: `403` or `429`
- Optional response delay in milliseconds
- IP whitelist support
- User-Agent whitelist support
- URI-based custom detection levels
- Support for exact paths, wildcards, prefix-style URI matching, and IPv4 CIDR
- Structured event logging
- Incident cache file creation
- Email notification support
- External command execution on detection
- Works at server scope and in `VirtualHost`
- GPLv3-friendly licensing model

---

## Installation

### Source checkout

Clone the repository:

```sh
git clone https://github.com/BuriXon-code/mod_doscontrol.git
cd mod_doscontrol
```

### Build prerequisites

You need:

- Apache HTTP Server
- Apache development headers
- `apxs`
- a C compiler
- APR / APR-util development headers

`apxs` is Apache’s extension tool for compiling, installing, and enabling DSO modules. The standard workflow is to build with `-c`, install with `-i`, and activate the module in Apache config with `-a`.

### Debian / Ubuntu

Install the toolchain and Apache development package:

```sh
sudo apt update
sudo apt install apache2 apache2-dev build-essential
```

Then build, install, and enable the module in one go:

```sh
apxs -c -i -a mod_doscontrol.c
```

What this does:

- `-c` compiles the module
- `-i` installs the shared object into the Apache modules directory
- `-a` adds or activates the `LoadModule` line in Apache configuration

If you prefer to separate build and install steps, you can also run:

```sh
apxs -c mod_doscontrol.c
sudo apxs -i -a -n doscontrol mod_doscontrol.la
```

The package `apache2-dev` provides the Apache development files and `apxs` on Debian-based systems.

### Alpine Linux

Install Apache and the development package:

```sh
sudo apk add apache2 apache2-dev build-base
```

Then build, install, and enable:

```sh
apxs -c -i -a mod_doscontrol.c
```

What this does:

- compiles the module
- installs the resulting shared object
- updates Apache configuration to load it

On Alpine, `apache2-dev` provides the Apache development files and `apxs`.

### FreeBSD

Install Apache 2.4 and the matching development tools from packages or ports.

Then build and install with `apxs`:

```sh
apxs -c -i -a mod_doscontrol.c
```

Make sure the Apache toolchain you use includes `apxs` and the matching headers.

### RHEL / CentOS / Rocky / AlmaLinux

Install Apache and the development toolchain for your distribution, then build with `apxs`:

```sh
apxs -c -i -a mod_doscontrol.c
```

If your packaging splits runtime and development files, make sure the Apache development package is installed.

### Generic build notes

Apache modules are built as DSOs and loaded at runtime with `LoadModule`. The `apxs` tool is the normal way to compile and install these modules.

After installation, the module should be loaded from Apache configuration, either automatically through `apxs -a` or manually with `LoadModule`.

Example:

```apache
LoadModule doscontrol_module modules/mod_doscontrol.so
```

> [!NOTE]
> After installing the module, reload and restart Apache using `service apache2 reload/restart` or the equivalent for your platform.

> [!TIP]
> For proper operation and effective retrieval of the correct client IP address, I recommend having the `mod_repoteip` module loaded.
>  The module installs by default on most Apache2 instances.
> Load it using `LoadModule remoteip_module modules/mod_remoteip.so` in Apache2 config

---

## Usage

`mod_doscontrol` can be configured globally or inside a `VirtualHost`.

The module watches client IP, request URI, and User-Agent. It first applies whitelist rules, then evaluates page and site hit rates, then applies the configured detection response.

### Basic example

```apache
LoadModule doscontrol_module modules/mod_doscontrol.so

DOSHashTableSize 4097
DOSPageCount 12
DOSSiteCount 60
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 30
DOSResponseCode 429
DOSBlockDelay 250
DOSMainLog /var/log/apache2/mod_doscontrol.log
DOSCacheDir /tmp/mod_doscontrol
```

> See **sample.conf** file for more details.

---

### DOSHashTableSize

Sets the internal hash table size used for tracking request activity.

Default: `3097`

```apache
DOSHashTableSize 4097
```

- Use a larger value when you expect many unique clients.
- The value should be a positive integer.
- If the value is missing or invalid, the module falls back to the built-in default.
- Larger tables reduce collision pressure but consume more memory.
- For smaller sites, the default is usually fine.

---

### DOSPageCount

Controls how many requests to the same URI are allowed inside the per-page time window before the module treats the client as abusive.

Default: `10`

```apache
DOSPageCount 12
```

- The value is an integer threshold.
- This is checked per URI, not across the whole site.
- Lower values make the module more aggressive.
- Higher values reduce false positives for busy pages.
- Good targets are login forms, API endpoints, search pages, and submission endpoints.

---

### DOSSiteCount

Controls how many requests across the whole site are allowed inside the site-wide time window before the module reacts.

Default: `50`

```apache
DOSSiteCount 60
```

- The value is an integer threshold.
- This checks total activity from one client, not just one URL.
- It is useful when the attacker spreads requests across many paths.
- Lower values make the module stricter.
- Higher values make it more tolerant of active but legitimate users.

---

### DOSPageInterval

Sets the per-page counting window in seconds.

Default: `1`

```apache
DOSPageInterval 1
```

- The value is a number of seconds.
- It defines the time window used by the page counter.
- Short intervals catch bursts quickly.
- Longer intervals make the detector less twitchy.
- In practice, `1` second is a common anti-burst choice.

---

### DOSSiteInterval

Sets the site-wide counting window in seconds.

Default: `1`

```apache
DOSSiteInterval 1
```

- The value is a number of seconds.
- It defines the time window used by the site counter.
- Short intervals are better for detecting sudden floods.
- Longer intervals smooth out slower request patterns.
- The page and site windows do not have to match, but matching them is often simpler.

---

### DOSBlockingPeriod

Sets how long, in seconds, a client remains blocked after a detection event.

Default: `30`

```apache
DOSBlockingPeriod 30
```

- The value is an integer number of seconds.
- Once a client is blocked, requests from that client remain blocked during this period.
- A longer period gives more breathing room under attack.
- A shorter period allows faster recovery for borderline traffic.
- Use a longer value for noisy repeat offenders.

---

### DOSResponseCode

Selects the HTTP response code sent to a detected client.

Default: `403`

```apache
DOSResponseCode 429
```

- The module accepts only `403` or `429`.
- `403` means Forbidden.
- `429` means Too Many Requests.
- `429` is the more natural fit for rate-style abuse handling.
- `403` is simpler and still perfectly valid.

---

### DOSBlockDelay

Adds an artificial delay before sending the blocked response.

Default: `0`

```apache
DOSBlockDelay 250
```

- The value is in milliseconds.
- `0` disables the delay completely.
- Positive values slow down blocked replies.
- The code reads this as an integer millisecond value.
- Negative values should not be used; treat them as invalid and keep the value at zero.
- This is useful when you want to waste attacker time without changing the blocking logic itself.

---

### DOSMainLog

Sets the path of the main module log file.

Default: `/var/log/apache2/mod_doscontrol.log`

```apache
DOSMainLog /var/log/apache2/mod_doscontrol.log
```

- The value is a filesystem path.
- The module writes allow/block/mail/command/cache events here.
- If you do not set it, the built-in default path is used.
- Choose a path writable by Apache or the process writing the log.
- This is the best place to keep long-term detection records.

---

### DOSCacheDir

Sets the directory used for incident cache files.

Default: `/tmp/mod_doscontrol`

```apache
DOSCacheDir /tmp/mod_doscontrol
```

- The value is a filesystem directory.
- The module creates one incident cache file per blocked client.
- If the directory does not exist, the module tries to create it.
- This is useful for external tooling, post-processing, or watchdog scripts.
- Keep it on a location that the Apache process can access.

---

### DOSEmailNotify

Sets the email address that receives notification messages when a client is blocked.

Default: not set

```apache
DOSEmailNotify admin@example.com
```

- The value must be a single email address string.
- The module uses that address as the recipient.
- If this is not configured, mail notifications are skipped.
- This is a notification hook, not a mail queue system.
- Use a working local MTA or mail command environment if you enable it.

---

### DOSSystemCommand

Runs an external command when a client is blocked.

Default: not set

```apache
DOSSystemCommand /usr/local/bin/notify-block.sh %s
```

- The value is a command template string.
- `%s` is replaced with the client IP.
- `%%` is replaced with a literal percent sign.
- The module executes the expanded command with the system shell.
- Keep the command simple and controlled.
- This is ideal for scripts that notify, log, rate-tag, or hand off to another security system.
- Do not point this at uncontrolled shell logic.

---

### DOSWhitelistIP

Adds a whitelisted IP rule.

Default: none

```apache
DOSWhitelistIP 127.0.0.1
DOSWhitelistIP 192.168.1.*
DOSWhitelistIP 10.0.0.0/8
DOSWhitelistIP 203.0.113.10
```

- The value can be an exact IPv4 address.
- Wildcards `*` and `?` are supported.
- CIDR notation is supported for IPv4.
- Whitelisted IPs bypass the detection logic.
- Use this for localhost, internal networks, trusted monitoring systems, and reverse proxy sources.
- The match happens before request counting.

---

### DOSWhitelistUA

Adds a whitelisted User-Agent rule.

Default: none

```apache
DOSWhitelistUA curl*
DOSWhitelistUA *HealthChecker*
DOSWhitelistUA Mozilla/5.?
```

- The value is a glob-style pattern.
- Matching is case-insensitive.
- `*` and `?` are supported.
- Whitelisted User-Agents bypass the detection logic.
- Use this for health checks, internal scanners, trusted bots, and automation clients.
- The match happens before request counting.

---

### DOSCustomLevel

Custom levels let you assign different request thresholds to selected URI patterns.

Default: disabled until configured

This module exposes 10 levels:

- `DOSCustomLevelCount1` / `DOSCustomLevelAdd1`
- `DOSCustomLevelCount2` / `DOSCustomLevelAdd2`
- `DOSCustomLevelCount3` / `DOSCustomLevelAdd3`
- `DOSCustomLevelCount4` / `DOSCustomLevelAdd4`
- `DOSCustomLevelCount5` / `DOSCustomLevelAdd5`
- `DOSCustomLevelCount6` / `DOSCustomLevelAdd6`
- `DOSCustomLevelCount7` / `DOSCustomLevelAdd7`
- `DOSCustomLevelCount8` / `DOSCustomLevelAdd8`
- `DOSCustomLevelCount9` / `DOSCustomLevelAdd9`
- `DOSCustomLevelCount10` / `DOSCustomLevelAdd10`

```apache
DOSCustomLevelCount1 3
DOSCustomLevelAdd1 /login
DOSCustomLevelAdd1 /admin/*
DOSCustomLevelAdd1 /api/auth/*

DOSCustomLevelCount2 5
DOSCustomLevelAdd2 /cart
DOSCustomLevelAdd2 /checkout
DOSCustomLevelAdd2 /account/*

DOSCustomLevelCount3 10
DOSCustomLevelAdd3 /search
DOSCustomLevelAdd3 /news/*
DOSCustomLevelAdd3 /products/*
```

- `CountN` sets the request threshold for that level.
- `AddN` adds URI patterns to that level.
- The code checks the configured URI patterns in order.
- `*` and `?` wildcard matching is supported.
- Prefix-style URI patterns such as `/admin/*` are ideal for whole sections.
- Exact URIs such as `/login` are good for single sensitive endpoints.
- The threshold value should be a positive integer.
- A higher count means a looser rule.
- A lower count means stricter protection.

Suggested level ideas:

- Level 1: login, admin, auth
- Level 2: cart, checkout, account
- Level 3: search, content feeds, product pages
- Level 4: downloads, gallery, blog archives
- Level 5: API read endpoints
- Level 6: dashboard pages
- Level 7: reporting pages
- Level 8: partner zones
- Level 9: internal tools
- Level 10: large public content groups

> [!WARNING]
> Do not reuse the same custom level many times across global scope and `VirtualHost` blocks. The module supports layered configuration, but duplicating the same level in several places may cause one implementation to shadow another instead of combining the rules the way you expect.

> [!TIP]
> When configuring `mod_doscontrol`, make sure your server paths and URIs are consistent with trailing slashes.  
> For example:
> - `/example` vs `/example/`  
> Misplaced or missing slashes can cause rules to not match as expected.
>
> Always double-check your server configuration to ensure correct path matching.

---

## VirtualHost usage

`mod_doscontrol` can be used globally or per virtual host.

### Server-wide configuration

```apache
LoadModule doscontrol_module modules/mod_doscontrol.so

DOSHashTableSize 4097
DOSPageCount 12
DOSSiteCount 60
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 30
DOSResponseCode 429
DOSBlockDelay 250
DOSMainLog /var/log/apache2/mod_doscontrol.log
DOSCacheDir /tmp/mod_doscontrol
```

### VirtualHost example

```apache
<VirtualHost *:80>
	ServerName example.com
	DocumentRoot /var/www/example.com/public_html

	DOSPageCount 8
	DOSSiteCount 40
	DOSBlockingPeriod 60
	DOSResponseCode 429
	DOSBlockDelay 300
	DOSMainLog /var/log/apache2/example.com-doscontrol.log
	DOSCacheDir /tmp/mod_doscontrol-example

	DOSWhitelistIP 127.0.0.1
	DOSWhitelistIP 10.0.0.0/8
	DOSWhitelistUA curl*
	DOSWhitelistUA *HealthChecker*

	DOSCustomLevelCount1 3
	DOSCustomLevelAdd1 /login
	DOSCustomLevelAdd1 /admin/*
	DOSCustomLevelAdd1 /api/auth/*

	DOSCustomLevelCount2 5
	DOSCustomLevelAdd2 /search
	DOSCustomLevelAdd2 /checkout
	DOSCustomLevelAdd2 /cart

	DOSSystemCommand /usr/local/bin/notify-detect.sh %s
	DOSEmailNotify admin@example.com
</VirtualHost>
```

This is the recommended way if you want different detection sensitivity per site.

#### Recommended approach

Set the following directives **globally** (in main server config):

```apache
DOSHashTableSize 3097
DOSPageCount 10
DOSSiteCount 50
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 30
DOSCacheDir /tmp/mod_doscontrol
DOSMainLog /var/log/apache2/mod_doscontrol.log
DOSEmailNotify admin@example.com
DOSSystemCommand "/usr/local/bin/firewall-block %s"
```

- These define the core detection logic and shared resources
- Keeps behavior consistent across all VirtualHosts
- Prevents duplication and conflicting limits
- Ensures one central logging and response pipeline

Then use `VirtualHost` blocks for **customization and exceptions**:

```apache
<VirtualHost *:80>
	ServerName example.com

	DOSResponseCode 429

	DOSWhitelistIP 127.0.0.1
	DOSWhitelistIP 192.168.*.*
	DOSWhitelistUA "Googlebot*"

	DOSCustomLevelCount1 5
	DOSCustomLevelAdd1 "/login"
	DOSCustomLevelAdd1 "/api/auth/*"
</VirtualHost>
```

- Override response behavior per site (e.g. 403 vs 429)
- Add whitelists specific to a service (bots, internal tools, APIs)
- Tune sensitivity using `DOSCustomLevel` for specific endpoints
- Adapt detection to application-specific traffic patterns

#### Why this matters

Mixing everything everywhere *works*, but quickly becomes messy:

- multiple cache dirs → harder incident tracking  
- duplicated thresholds → unpredictable blocking  
- different system commands → inconsistent mitigation  

Keeping the **core global** and **logic local** gives you:

- predictable behavior  
- easier debugging  
- cleaner configuration  
- safer scaling across multiple domains  

> [!WARNING]
> Avoid redefining the same `DOSCustomLevel` (e.g. Level1) multiple times across global and VirtualHost scopes.  
> While the module will merge configurations, overlapping patterns and thresholds may lead to unexpected matching behavior.

---

## Example configurations

### High-sensitivity login protection

```apache
DOSPageCount 3
DOSSiteCount 20
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 60
DOSResponseCode 429
DOSBlockDelay 500
DOSCustomLevelCount1 2
DOSCustomLevelAdd1 /login
DOSCustomLevelAdd1 /admin/*
DOSCustomLevelAdd1 /api/login
```

### General public site protection

```apache
DOSPageCount 12
DOSSiteCount 60
DOSPageInterval 1
DOSSiteInterval 1
DOSBlockingPeriod 30
DOSResponseCode 429
DOSBlockDelay 100
DOSCustomLevelCount2 8
DOSCustomLevelAdd2 /search
DOSCustomLevelAdd2 /cart
DOSCustomLevelAdd2 /checkout
```

### Quiet logging mode with detection only

```apache
DOSPageCount 15
DOSSiteCount 80
DOSBlockingPeriod 10
DOSResponseCode 403
DOSBlockDelay 0
DOSMainLog /var/log/apache2/mod_doscontrol.log
```

---

## Notes

- This module is intended for detection and reaction, not just hard blocking.
- The response delay is optional and disabled by default.
- Custom URI levels let you tighten limits on sensitive endpoints.
- Whitelists are processed before rate checks.
- The module can help with traffic analysis, event logging, and automation pipelines.
- For security reasons, keep `DOSSystemCommand` pointed at a trusted script or program only.
- If a directive is omitted, the built-in defaults shown above apply.
- The defaults already cover sane paths for logs and cache files, so you only need to override them when you actually want a different location.

---

## License

"mod_doscontrol" is released under the **GNU General Public License version 3** (GPLv3), or (at your option) any later version.

This project is based on concepts and portions of code derived from "mod_evasive", originally created by Jonathan A. Zdziarski, and licensed under the GNU General Public License version 2 (GPLv2), or (at your option) any later version.

"mod_doscontrol" is an independent refactor and rework by **Kamil "BuriXon" Burek**.

> See the **LICENSE** file for full license terms.
> See the **NOTICE** file for detailed attribution and copyright information.

If you redistribute or modify this project, you must comply with the terms of the GPL. In particular, you must preserve all existing copyright and license notices, including those of:

- Kamil "BuriXon" Burek
- Jonathan A. Zdziarski ("mod_evasive")

This requirement applies to any redistribution or derivative work, in whole or in part.

---

## Support

### Contact me:
For any issues, suggestions, or questions, reach out via:

- *Email:* support@burixon.dev
- *Contact form:* [Click here](https://burixon.dev/contact/)
- *Bug reports:* [Click here](https://burixon.dev/bugreport/#mod_doscontrol)

### Support me:
If you find this project useful, consider supporting my work by making a donation:

Click [**Donations**](https://burixon.dev/donate/), then click the cup :)

Your contributions help in developing new projects and improving existing tools!
