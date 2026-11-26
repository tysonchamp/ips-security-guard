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
	 * Check whether an IP address matches an exact IP or CIDR range (IPv4 or IPv6).
	 *
	 * @param string $ip
	 * @param string $range
	 * @return bool
	 */
	public static function ip_matches_range( $ip, $range ) {
		$ip    = trim( (string) $ip );
		$range = trim( (string) $range );

		if ( empty( $ip ) || empty( $range ) ) {
			return false;
		}

		if ( strpos( $range, '/' ) === false ) {
			$ip_bin    = @inet_pton( $ip );
			$range_bin = @inet_pton( $range );
			return ( false !== $ip_bin && $ip_bin === $range_bin );
		}

		list( $subnet, $prefix ) = explode( '/', $range, 2 );
		if ( ! is_numeric( $prefix ) ) {
			return false;
		}

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( trim( $subnet ) );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$max_bits = strlen( $ip_bin ) * 8;
		$prefix   = (int) $prefix;
		if ( $prefix < 0 || $prefix > $max_bits ) {
			return false;
		}

		$full_bytes = intdiv( $prefix, 8 );
		$rem_bits   = $prefix % 8;

		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $subnet_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( $rem_bits > 0 ) {
			$mask = ( 0xFF << ( 8 - $rem_bits ) ) & 0xFF;
			if ( ( ord( $ip_bin[ $full_bytes ] ) & $mask ) !== ( ord( $subnet_bin[ $full_bytes ] ) & $mask ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Get configured list of trusted reverse proxy IPs or CIDR ranges.
	 *
	 * @return array
	 */
	public static function get_trusted_proxies() {
		$settings = get_option( 'ips_security_settings', array() );
		$raw      = isset( $settings['trusted_proxies'] ) ? (string) $settings['trusted_proxies'] : '';
		$proxies  = array_values( array_filter( array_map( 'trim', preg_split( '/[\r\n,]+/', $raw ) ) ) );

		if ( function_exists( 'apply_filters' ) ) {
			$proxies = apply_filters( 'ips_security_trusted_proxies', $proxies );
		}

		return is_array( $proxies ) ? $proxies : array();
	}

	/**
	 * Check if an IP belongs to the trusted proxies list.
	 *
	 * @param string $ip
	 * @param array  $trusted_proxies
	 * @return bool
	 */
	public static function is_trusted_proxy( $ip, $trusted_proxies ) {
		foreach ( $trusted_proxies as $range ) {
			if ( self::ip_matches_range( $ip, $range ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get sanitized client IP address without trusting spoofable headers from untrusted peers.
	 *
	 * @return string
	 */
	public static function get_client_ip() {
		$remote_addr = ! empty( $_SERVER['REMOTE_ADDR'] ) ? trim( (string) $_SERVER['REMOTE_ADDR'] ) : '';
		$remote_ip   = filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : '127.0.0.1';

		$trusted_proxies = self::get_trusted_proxies();
		if ( empty( $trusted_proxies ) || ! self::is_trusted_proxy( $remote_ip, $trusted_proxies ) ) {
			return $remote_ip;
		}

		// Trust Cloudflare header when REMOTE_ADDR is a verified trusted proxy.
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$cf_ip = trim( (string) $_SERVER['HTTP_CF_CONNECTING_IP'] );
			if ( filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
				return $cf_ip;
			}
		}

		// Walk X-Forwarded-For right-to-left and pick the first valid non-proxy hop.
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts = array_reverse( explode( ',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			foreach ( $parts as $part ) {
				$candidate = trim( $part );
				if ( filter_var( $candidate, FILTER_VALIDATE_IP ) && ! self::is_trusted_proxy( $candidate, $trusted_proxies ) ) {
					return $candidate;
				}
			}
		}

		return $remote_ip;
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
