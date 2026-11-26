=== IPS Security Guard ===
Contributors: tysonchamp
Tags: security, firewall, hardening, htaccess, brute force, protection
Requires at least: 5.0
Tested up to: 7.1
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight, high-performance WordPress security hardening, web application firewall (WAF), and brute-force mitigation engine.

== Description ==

IPS Security Guard is a custom, zero-bloat security plugin engineered specifically for the Indian Public School website. It provides comprehensive security without external cloud dependencies or server performance penalties.

= Key Features =

* **Server .htaccess Firewall:** Automatically blocks database dumps (.sql), .git repositories, .env files, backup files, and sensitive configurations.
* **Uploads PHP Lockdown:** Blocks direct execution of PHP scripts and executables inside `wp-content/uploads/`.
* **Application Firewall (WAF):** Real-time protection against SQL Injection, Reflected XSS, Directory Traversal, and Null Byte exploits.
* **Scanner & Bad Bot Defense:** Identifies and blocks automated scanning tools (sqlmap, nikto, acunetix, dirbuster, nmap, etc.).
* **Brute-Force Login Shield:** Spoof-proof IP rate limiting using `REMOTE_ADDR` (with configurable trusted proxy IPs/CIDRs), 5-attempt / 15-minute lockouts, and obscured login errors.
* **Core Hardening:** Optional XML-RPC blocking, optional `DISALLOW_FILE_MODS` lock to block plugin/theme ZIP uploads and updates, version disclosure removal, REST API user enumeration restriction, and `?author=N` blocking.
* **Security HTTP Response Headers:** Emits X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, and Permissions-Policy.
* **Malicious Upload Guard:** Rejects dangerous extensions, double-extension bypasses (e.g. image.php.jpg), plugin/theme ZIP uploads when locked, and optional archive uploads.
* **Admin Dashboard & Audit Log:** View live protection status, configure security options, and review audit logs from WP Admin > IPS Security.

== Installation ==

1. Upload the `ips-security-guard` directory to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Visit 'IPS Security' in the WordPress admin menu to monitor security status and review audit logs.

== Changelog ==

= 1.2.0 =
* Fixed brute-force IP spoofing by using REMOTE_ADDR unless the peer matches an explicitly configured trusted reverse proxy IP/CIDR.
* Added optional `DISALLOW_FILE_MODS` lock (enabled by default) to block unauthorized plugin/theme ZIP uploads, installs, and updates in wp-admin.
* Added plugin/theme `.zip` upload blocking in Upload Guard when file modifications are locked, plus an optional toggle to block general archive uploads.
* Hardened `wp-content/uploads/.htaccess` with `<FilesMatch>` alongside `mod_rewrite` rules and case-insensitive root `.htaccess` extension rules.

= 1.1.0 =
* Added toggle setting to enable or disable XML-RPC protection.
* Added directory browsing (`Options -Indexes`), `.htaccess` protection, and expanded sensitive file rules.

= 1.0.0 =
* Initial release with full security hardening, WAF, brute force shield, and uploads protection.
