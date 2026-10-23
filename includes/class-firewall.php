<?php
/**
 * Application Firewall and Request Inspector
 *
 * @package IPS_Security_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IPS_Security_Firewall {

	/**
	 * Initialize firewall hooks
	 */
	public static function init() {
		// Run early to intercept requests before core logic
		add_action( 'plugins_loaded', array( __CLASS__, 'inspect_request' ), 1 );
	}

	/**
	 * Inspect the current request for malicious patterns
	 */
	public static function inspect_request() {
		// Skip CLI requests
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		// Don't block logged-in administrators in admin dashboard
		if ( is_admin() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$request_uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : '';
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? (string) $_SERVER['QUERY_STRING'] : '';

		// 1. Check for Directory Traversal
		if ( preg_match( '/(\.\.[\/\\\\]|\.\.%2f|%2e%2e[\/\\\\])/i', $request_uri ) ) {
			self::block_request( 'Directory Traversal Attempt' );
		}

		// 2. Check for Null Byte Injection
		if ( strpos( $request_uri, '%00' ) !== false || strpos( $request_uri, "\0" ) !== false ) {
			self::block_request( 'Null Byte Injection' );
		}

		// 3. Check for SQL Injection & XSS in Query String
		if ( ! empty( $query_string ) ) {
			$decoded_query = rawurldecode( $query_string );

			$sqli_patterns = array(
				'/(union\s+(all\s+)?select)/i',
				'/(select\s+.*\s+from)/i',
				'/(or\s+["\']?1["\']?\s*=\s*["\']?1)/i',
				'/(sleep\s*\([0-9]+\))/i',
				'/(benchmark\s*\([0-9]+)/i',
				'/(concat\s*\(.*\))/i',
				'/(char\s*\([0-9]+\))/i',
				'/(drop\s+table)/i',
				'/(information_schema)/i',
			);

			foreach ( $sqli_patterns as $pattern ) {
				if ( preg_match( $pattern, $query_string ) || preg_match( $pattern, $decoded_query ) ) {
					self::block_request( 'SQL Injection Attempt' );
				}
			}

			// 4. Check for Reflected XSS Script Injections in Query String
			$xss_patterns = array(
				'/(<|%3C)\s*script/i',
				'/(javascript\s*:)/i',
				'/(onload|onerror|onclick|onmouseover|onfocus)\s*=/i',
				'/(document\.(cookie|location|write))/i',
			);

			foreach ( $xss_patterns as $pattern ) {
				if ( preg_match( $pattern, $query_string ) || preg_match( $pattern, $decoded_query ) ) {
					self::block_request( 'Cross-Site Scripting (XSS) Attempt' );
				}
			}
		}

		// 5. Block Suspicious User Agents (known offensive scanner tools)
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
		if ( ! empty( $user_agent ) ) {
			$bad_bots = array(
				'sqlmap', 'nikto', 'havij', 'acunetix', 'dirbuster', 'gobuster', 'masscan', 'nmap'
			);
			foreach ( $bad_bots as $bot ) {
				if ( stripos( $user_agent, $bot ) !== false ) {
					self::block_request( 'Vulnerability Scanner Detected (' . esc_html( $bot ) . ')' );
				}
			}
		}
	}

	/**
	 * Terminate request and record security event
	 *
	 * @param string $reason
	 */
	public static function block_request( $reason ) {
		$ip = self::get_client_ip();

		self::log_event( array(
			'type'   => 'Firewall Block',
			'reason' => $reason,
			'ip'     => $ip,
			'uri'    => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( $_SERVER['REQUEST_URI'] ) : '',
			'time'   => current_time( 'mysql' ),
		) );

		wp_die(
			'<h3>Security Alert</h3><p>Access blocked by IPS Security Guard: ' . esc_html( $reason ) . '</p>',
			'Forbidden - 403',
			array( 'response' => 403 )
		);
	}

	/**
	 * Get sanitized client IP address
	 *
	 * @return string
	 */
	public static function get_client_ip() {
		$ip = '127.0.0.1';

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
			$ip    = trim( $parts[0] );
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = $_SERVER['REMOTE_ADDR'];
		}

		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '127.0.0.1';
	}

	/**
	 * Log security event to WordPress database (capped at 50 entries)
	 *
	 * @param array $event
	 */
	public static function log_event( $event ) {
		$logs = get_option( 'ips_security_logs', array() );
		if ( ! is_array( $logs ) ) {
			$logs = array();
		}

		array_unshift( $logs, $event );

		// Keep only last 50 entries
		if ( count( $logs ) > 50 ) {
			$logs = array_slice( $logs, 0, 50 );
		}

		update_option( 'ips_security_logs', $logs, false );
	}
}
