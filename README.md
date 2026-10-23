# IPS Security Guard

**IPS Security Guard** is a lightweight, zero-bloat, high-performance WordPress security hardening, web application firewall (WAF), and brute-force mitigation plugin built specifically for the Indian Public School website.

---

## Features

### 1. Automated Server & `.htaccess` Protection
* **Uploads Directory PHP Lockdown:** Automatically injects and maintains rules in both the site root `.htaccess` and `wp-content/uploads/.htaccess` to block direct execution of `.php`, `.phtml`, `.phps`, `.phar`, and executable scripts.
* **Sensitive Files & Database Dump Protection:** Completely blocks direct HTTP access to database dumps (`.sql`), `.git` repositories, `.env` environment files, backup files (`.bak`), configuration files (`.ini`, `.conf`), and log files (`.log`).
* **Critical File Cloaking:** Forbids web access to `wp-config.php`, `readme.html`, and `license.txt` (preventing WordPress version and configuration disclosure).
* **One-Click Rule Verification:** Provides a button in the admin dashboard to verify and re-apply all `.htaccess` hardening rules if they are ever overwritten.

### 2. Real-Time Application Firewall (WAF)
* **SQL Injection (SQLi) Protection:** Inspects raw and decoded query strings for common SQL injection attack signatures (`UNION SELECT`, `SLEEP()`, `BENCHMARK()`, `information_schema`, comment injection) and immediately aborts malicious requests with a `403 Forbidden`.
* **Cross-Site Scripting (XSS) Shield:** Detects and blocks requests containing `<script>`, `javascript:`, DOM event handlers (`onload=`, `onerror=`), and cookie-stealing payloads.
* **Directory Traversal & Null Byte Defense:** Blocks path traversal (`../`, `..\`) and null byte (`%00`, `\0`) injection exploits.
* **Bad Bot & Vulnerability Scanner Blocker:** Identifies and blocks automated scanning tools such as `sqlmap`, `nikto`, `acunetix`, `dirbuster`, `gobuster`, and `nmap`.

### 3. Core Hardening & Information Disclosure Prevention
* **XML-RPC Completely Disabled:** Eliminates DDoS amplification attacks and automated brute-force attacks by disabling the XML-RPC API and removing `X-Pingback` headers.
* **User & Author Enumeration Defense:**
  * Blocks `?author=N` query scanning used by scanners (like WPScan) to discover admin usernames.
  * Restricts unauthenticated access to the WordPress REST API users endpoint (`/wp-json/wp/v2/users`).
* **HTTP Security Headers:** Automatically delivers security headers on every front-end response:
  * `X-Content-Type-Options: nosniff`
  * `X-Frame-Options: SAMEORIGIN`
  * `X-XSS-Protection: 1; mode=block`
  * `Referrer-Policy: strict-origin-when-cross-origin`
  * `Permissions-Policy: camera=(), microphone=(), geolocation=()`
* **Version String Removal:** Removes the `the_generator` WordPress version tag from `<head>` and RSS feeds, and removes `?ver=` query strings from CSS/JS assets for guests.
* **Code Editor Lockdown:** Enforces `DISALLOW_FILE_EDIT` to prevent code injection via the WordPress Theme/Plugin File Editor in `wp-admin`.

### 4. Brute-Force Login Shield
* **Obscured Login Errors:** Replaces specific WordPress error messages with a generic `"Invalid username or password"` notification, stopping attackers from confirming valid usernames.
* **IP Rate Limiting & Lockout:** Automatically tracks failed login attempts and locks out offending IP addresses for 15 minutes after 5 consecutive failed attempts.
* **Automatic Reset:** Clears failed attempts immediately upon successful authentication.

### 5. Malicious File Upload Guard
* **Pre-Upload File Inspection:** Intercepts uploads before they are saved to disk via `wp_handle_upload_prefilter`.
* **Dangerous Extension Blocker:** Rejects scripts and executable extensions (`.php`, `.phtml`, `.cgi`, `.sh`, `.exe`, `.phar`, `.vbs`, etc.).
* **Double-Extension Blocker:** Detects and rejects bypass tricks such as `image.php.jpg` or `shell.phtml.png`.

### 6. Admin Security Dashboard & Audit Logging
* **Security Status Dashboard:** View live status indicators for all protection layers directly from **WP Admin > IPS Security**.
* **Audit Logging:** Captures blocked attacks (timestamp, event type, blocked IP, and attack reason) into a clean, searchable log table.
* **One-Click Maintenance:** Allows administrators to reapply rules or clear audit logs with WordPress nonce verification.

---

## File Structure

```
ips-security-guard/
├── README.md                      # Documentation
├── ips-security-guard.php         # Main bootstrap & lifecycle hooks
└── includes/
    ├── class-admin.php            # Admin dashboard UI & log viewer
    ├── class-firewall.php         # Real-time request inspection & WAF
    ├── class-hardening.php        # Core hardening, XML-RPC & security headers
    ├── class-htaccess.php         # Server .htaccess rules manager
    ├── class-login-shield.php     # Brute-force rate limiting & login shield
    └── class-upload-guard.php     # Upload file extension & double-extension filter
```

---

## Requirements

* **WordPress:** 5.0 or higher
* **PHP:** 7.4 or higher (fully compatible with PHP 8.0, 8.1, 8.2, 8.3+)
* **Web Server:** Apache with `mod_rewrite` enabled

---

## Installation

1. Upload the `ips-security-guard` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin via **Plugins > Installed Plugins** in WordPress.
3. Upon activation, the plugin automatically configures the necessary `.htaccess` rules and enables all security modules.
4. Navigate to **WP Admin > IPS Security** to view the live security status and audit log.

---

## License

GPL v2 or later. Developed for Indian Public School (IPS Howrah).
