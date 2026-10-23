<?php
/**
 * Upload Guard & Malicious File Filter
 *
 * @package IPS_Security_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IPS_Security_Upload_Guard {

	/**
	 * Forbidden file extensions that should never be uploaded
	 *
	 * @var array
	 */
	private static $dangerous_extensions = array(
		'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phtml', 'phps',
		'phar', 'pl', 'py', 'cgi', 'sh', 'bash', 'exe', 'bat', 'cmd', 'vbs',
		'htaccess', 'htpasswd', 'ini', 'sql', 'sh'
	);

	/**
	 * Initialize upload guard hooks
	 */
	public static function init() {
		add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'filter_uploads' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure_uploads_htaccess' ) );
	}

	/**
	 * Filter and validate uploads before they are processed by WordPress
	 *
	 * @param array $file
	 * @return array
	 */
	public static function filter_uploads( $file ) {
		$filename = isset( $file['name'] ) ? strtolower( (string) $file['name'] ) : '';

		if ( empty( $filename ) ) {
			return $file;
		}

		// 1. Detect direct dangerous extensions
		$ext = pathinfo( $filename, PATHINFO_EXTENSION );
		if ( in_array( $ext, self::$dangerous_extensions, true ) ) {
			$file['error'] = 'Security Alert: Uploading executable or script files is strictly forbidden.';
			self::log_upload_block( $filename, 'Executable extension (.' . $ext . ')' );
			return $file;
		}

		// 2. Detect double extensions (e.g. evil.php.jpg, shell.phtml.png)
		$parts = explode( '.', $filename );
		if ( count( $parts ) > 2 ) {
			array_pop( $parts ); // Remove final extension
			foreach ( $parts as $part ) {
				if ( in_array( $part, self::$dangerous_extensions, true ) ) {
					$file['error'] = 'Security Alert: Suspicious double extension detected in file name.';
					self::log_upload_block( $filename, 'Double extension hiding executable payload (.' . $part . ')' );
					return $file;
				}
			}
		}

		// 3. Detect null byte in filename
		if ( strpos( $filename, "\0" ) !== false || strpos( $filename, '%00' ) !== false ) {
			$file['error'] = 'Security Alert: Malformed file name detected.';
			self::log_upload_block( $filename, 'Null byte injection in file name' );
			return $file;
		}

		return $file;
	}

	/**
	 * Ensure that wp-content/uploads/.htaccess is present
	 */
	public static function ensure_uploads_htaccess() {
		if ( ! IPS_Security_Htaccess::is_uploads_protected() ) {
			IPS_Security_Htaccess::apply_rules();
		}
	}

	/**
	 * Log blocked upload attempt
	 *
	 * @param string $filename
	 * @param string $reason
	 */
	private static function log_upload_block( $filename, $reason ) {
		IPS_Security_Firewall::log_event( array(
			'type'   => 'Malicious Upload Blocked',
			'reason' => $reason . ' (Filename: ' . sanitize_file_name( $filename ) . ')',
			'ip'     => IPS_Security_Firewall::get_client_ip(),
			'uri'    => 'async-upload.php',
			'time'   => current_time( 'mysql' ),
		) );
	}
}
