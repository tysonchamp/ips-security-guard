=== IPS Security Guard ===
Contributors: tysonchamp
Tags: security, firewall, hardening, htaccess, brute force, protection
Requires at least: 5.0
Tested up to: 7.1
Stable tag: 1.0.0
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
* **Brute-Force Login Shield:** Rate limits login attempts (5 attempts in 15 minutes = 15-minute IP lockout) and obscures login errors.
* **Core Hardening:** Completely disables XML-RPC, strips version disclosures, restricts REST API user enumeration, and blocks ?author=N scanning.
* **Security HTTP Response Headers:** Emits X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, and Permissions-Policy.
* **Malicious Upload Guard:** Rejects dangerous extensions and double-extension bypasses (e.g. image.php.jpg).
* **Admin Dashboard & Audit Log:** View live protection status and audit logs from WP Admin > IPS Security.

== Installation ==

1. Upload the `ips-security-guard` directory to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Visit 'IPS Security' in the WordPress admin menu to monitor security status and review audit logs.

== Changelog ==

= 1.0.0 =
* Initial release with full security hardening, WAF, brute force shield, and uploads protection.
