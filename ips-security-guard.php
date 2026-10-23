<?php
/**
 * Plugin Name:       IPS Security Guard
 * Plugin URI:        https://www.tysonchamp.com/
 * Description:       Advanced WordPress security hardening, application firewall, brute-force shield, and .htaccess protection.
 * Version:           1.0.0
 * Author:            Tyson Champ
 * Author URI:        https://www.tysonchamp.com/
 * License:           GPL v2 or later
 * Text Domain:       ips-security-guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'IPS_SECURITY_VERSION', '1.0.0' );
define( 'IPS_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'IPS_SECURITY_URL', plugin_dir_url( __FILE__ ) );

// Load Plugin Classes
require_once IPS_SECURITY_PATH . 'includes/class-htaccess.php';
require_once IPS_SECURITY_PATH . 'includes/class-firewall.php';
require_once IPS_SECURITY_PATH . 'includes/class-hardening.php';
require_once IPS_SECURITY_PATH . 'includes/class-login-shield.php';
require_once IPS_SECURITY_PATH . 'includes/class-upload-guard.php';

if ( is_admin() ) {
	require_once IPS_SECURITY_PATH . 'includes/class-admin.php';
}

/**
 * Initialize all security components
 */
function ips_security_guard_init() {
	// Inspect request immediately
	IPS_Security_Firewall::inspect_request();

	IPS_Security_Hardening::init();
	IPS_Security_Login_Shield::init();
	IPS_Security_Upload_Guard::init();

	if ( is_admin() ) {
		IPS_Security_Admin::init();
	}
}
add_action( 'plugins_loaded', 'ips_security_guard_init', 1 );

/**
 * Plugin Activation Callback
 */
function ips_security_guard_activate() {
	// Apply all security rules to .htaccess
	IPS_Security_Htaccess::apply_rules();
}
register_activation_hook( __FILE__, 'ips_security_guard_activate' );

/**
 * Plugin Deactivation Callback
 */
function ips_security_guard_deactivate() {
	// Clear any active lockout transients
	delete_transient( 'ips_sec_attempts_' );
}
register_deactivation_hook( __FILE__, 'ips_security_guard_deactivate' );
