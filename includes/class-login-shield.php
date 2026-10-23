<?php
/**
 * Login Shield & Brute Force Protection
 *
 * @package IPS_Security_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IPS_Security_Login_Shield {

	const MAX_ATTEMPTS   = 5;
	const LOCKOUT_PERIOD = 900; // 15 minutes in seconds

	/**
	 * Initialize login shield hooks
	 */
	public static function init() {
		// Obscure login error messages to prevent username enumeration
		add_filter( 'login_errors', array( __CLASS__, 'generic_login_error' ) );

		// Check lockout before authentication
		add_filter( 'authenticate', array( __CLASS__, 'check_lockout' ), 20, 3 );

		// Track failed attempts
		add_action( 'wp_login_failed', array( __CLASS__, 'track_failed_attempt' ) );

		// Clear failed attempts on successful login
		add_action( 'wp_login', array( __CLASS__, 'clear_failed_attempts' ), 10, 2 );
	}

	/**
	 * Return generic error message for all failed logins
	 *
	 * @return string
	 */
	public static function generic_login_error() {
		return '<strong>Error:</strong> Invalid username or password.';
	}

	/**
	 * Check if client IP is currently locked out
	 *
	 * @param WP_User|WP_Error|null $user
	 * @param string                $username
	 * @param string                $password
	 * @return WP_User|WP_Error
	 */
	public static function check_lockout( $user, $username, $password ) {
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$ip          = IPS_Security_Firewall::get_client_ip();
		$lockout_key = 'ips_sec_lockout_' . md5( $ip );

		if ( get_transient( $lockout_key ) ) {
			return new WP_Error(
				'ips_locked_out',
				'<strong>Account Protected:</strong> Too many failed login attempts from your IP address. Please try again after 15 minutes.'
			);
		}

		return $user;
	}

	/**
	 * Track failed login attempts by IP
	 *
	 * @param string $username
	 */
	public static function track_failed_attempt( $username ) {
		$ip           = IPS_Security_Firewall::get_client_ip();
		$attempts_key = 'ips_sec_attempts_' . md5( $ip );
		$attempts     = (int) get_transient( $attempts_key );
		$attempts++;

		if ( $attempts >= self::MAX_ATTEMPTS ) {
			$lockout_key = 'ips_sec_lockout_' . md5( $ip );
			set_transient( $lockout_key, 1, self::LOCKOUT_PERIOD );
			delete_transient( $attempts_key );

			IPS_Security_Firewall::log_event( array(
				'type'   => 'Brute Force Lockout',
				'reason' => 'IP locked out for 15 minutes after ' . self::MAX_ATTEMPTS . ' failed attempts (username: ' . sanitize_text_field( $username ) . ')',
				'ip'     => $ip,
				'uri'    => 'wp-login.php',
				'time'   => current_time( 'mysql' ),
			) );
		} else {
			set_transient( $attempts_key, $attempts, self::LOCKOUT_PERIOD );
		}
	}

	/**
	 * Clear failed attempt tracker on successful login
	 *
	 * @param string  $user_login
	 * @param WP_User $user
	 */
	public static function clear_failed_attempts( $user_login, $user ) {
		$ip = IPS_Security_Firewall::get_client_ip();
		delete_transient( 'ips_sec_attempts_' . md5( $ip ) );
		delete_transient( 'ips_sec_lockout_' . md5( $ip ) );
	}
}
