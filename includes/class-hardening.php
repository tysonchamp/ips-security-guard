<?php
/**
 * Core WordPress Security Hardening
 *
 * @package IPS_Security_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IPS_Security_Hardening {

	/**
	 * Initialize hardening filters & actions
	 */
	public static function init() {
		// 1. Send Security HTTP Headers
		add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ) );

		// 2. Disable XML-RPC completely
		add_filter( 'xmlrpc_enabled', '__return_false' );
		add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
		add_filter( 'xmlrpc_methods', '__return_empty_array' );

		// 3. Block User & Author Enumeration
		add_action( 'init', array( __CLASS__, 'block_author_scan' ) );
		add_filter( 'rest_endpoints', array( __CLASS__, 'restrict_rest_users_endpoint' ) );

		// 4. Information Disclosure Removal (WP Version)
		add_filter( 'the_generator', '__return_empty_string' );
		add_filter( 'script_loader_src', array( __CLASS__, 'remove_asset_version' ), 15 );
		add_filter( 'style_loader_src', array( __CLASS__, 'remove_asset_version' ), 15 );

		// 5. Ensure DISALLOW_FILE_EDIT constant is active
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
	}

	/**
	 * Send Security HTTP Headers
	 */
	public static function send_security_headers() {
		if ( ! is_admin() ) {
			header( 'X-Content-Type-Options: nosniff' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'X-XSS-Protection: 1; mode=block' );
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
			header( 'Permissions-Policy: camera=(), microphone=(), geolocation=()' );
		}
	}

	/**
	 * Remove X-Pingback from HTTP headers
	 *
	 * @param array $headers
	 * @return array
	 */
	public static function remove_pingback_header( $headers ) {
		if ( isset( $headers['X-Pingback'] ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * Block author username enumeration query string (?author=1)
	 */
	public static function block_author_scan() {
		if ( ! is_admin() && isset( $_REQUEST['author'] ) && ! current_user_can( 'manage_options' ) ) {
			IPS_Security_Firewall::log_event( array(
				'type'   => 'Author Scan Blocked',
				'reason' => 'Username Enumeration Attempt (?author=' . sanitize_text_field( $_REQUEST['author'] ) . ')',
				'ip'     => IPS_Security_Firewall::get_client_ip(),
				'uri'    => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( $_SERVER['REQUEST_URI'] ) : '',
				'time'   => current_time( 'mysql' ),
			) );

			wp_die( 'Access forbidden.', 'Forbidden - 403', array( 'response' => 403 ) );
		}
	}

	/**
	 * Restrict unauthenticated REST API user enumeration (/wp/v2/users)
	 *
	 * @param array $endpoints
	 * @return array
	 */
	public static function restrict_rest_users_endpoint( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			if ( isset( $endpoints['/wp/v2/users'] ) ) {
				unset( $endpoints['/wp/v2/users'] );
			}
			if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
				unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
			}
		}
		return $endpoints;
	}

	/**
	 * Remove ?ver= query string from styles and scripts for non-logged-in visitors
	 *
	 * @param string $src
	 * @return string
	 */
	public static function remove_asset_version( $src ) {
		if ( ! is_user_logged_in() && $src && strpos( $src, 'ver=' ) !== false ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}
}
