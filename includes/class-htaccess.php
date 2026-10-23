<?php
/**
 * Htaccess Security Rules Manager
 *
 * @package IPS_Security_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IPS_Security_Htaccess {

	const MARKER = 'IPS Security Hardening';

	/**
	 * Get the security rules to inject into root .htaccess
	 *
	 * @return string
	 */
	public static function get_root_rules() {
		$home_path = wp_parse_url( home_url(), PHP_URL_PATH );
		$base      = ! empty( $home_path ) ? trailingslashit( $home_path ) : '/';

		$rules  = "# BEGIN " . self::MARKER . "\n";
		$rules .= "<IfModule mod_rewrite.c>\n";
		$rules .= "RewriteEngine On\n";
		$rules .= "RewriteBase " . $base . "\n\n";
		$rules .= "# 1. Block access to hidden files and directories (e.g., .git, .env)\n";
		$rules .= "RewriteRule (^|/)\.(?!well-known) - [F,L]\n\n";
		$rules .= "# 2. Block direct web access to sensitive file extensions (database dumps, backups, configs)\n";
		$rules .= "RewriteRule \.(sql|bak|config|dist|fla|inc|ini|log|psd|sh|tar|zip|gz|env)$ - [F,L]\n\n";
		$rules .= "# 3. Block direct web access to wp-config.php and version disclosure files\n";
		$rules .= "RewriteRule ^wp-config\.php$ - [F,L]\n";
		$rules .= "RewriteRule ^(readme\.html|license\.txt) - [F,L]\n\n";
		$rules .= "# 4. Block access to xmlrpc.php to prevent DDoS amplification and brute-force attacks\n";
		$rules .= "RewriteRule ^xmlrpc\.php$ - [F,L]\n\n";
		$rules .= "# 5. Prevent executing PHP scripts inside uploads directory\n";
		$rules .= "RewriteRule ^wp-content/uploads/.*\.(?:php[0-9]*|pht|phtml|phps|phar)$ - [F,L,NC]\n";
		$rules .= "</IfModule>\n";
		$rules .= "# END " . self::MARKER . "\n";

		return $rules;
	}

	/**
	 * Apply security rules to root .htaccess and uploads .htaccess
	 *
	 * @return bool
	 */
	public static function apply_rules() {
		$root_htaccess = ABSPATH . '.htaccess';
		$success       = true;

		// 1. Update root .htaccess
		if ( file_exists( $root_htaccess ) && is_writable( $root_htaccess ) ) {
			$content = file_get_contents( $root_htaccess );
			$pattern = '/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\n?/s';

			$new_block = self::get_root_rules();

			if ( preg_match( $pattern, $content ) ) {
				$updated = preg_replace( $pattern, $new_block, $content );
			} else {
				// Prepend before standard WordPress rules
				$updated = $new_block . "\n" . ltrim( $content );
			}

			if ( false === file_put_contents( $root_htaccess, $updated ) ) {
				$success = false;
			}
		} elseif ( is_writable( ABSPATH ) ) {
			// File doesn't exist but directory is writable
			$default_wp = "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\nRewriteBase " . trailingslashit( wp_parse_url( home_url(), PHP_URL_PATH ) ?: '/' ) . "\nRewriteRule ^index\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . index.php [L]\n</IfModule>\n";
			$content    = self::get_root_rules() . "\n# BEGIN WordPress\n" . $default_wp . "# END WordPress\n";
			if ( false === file_put_contents( $root_htaccess, $content ) ) {
				$success = false;
			}
		} else {
			$success = false;
		}

		// 2. Protect wp-content/uploads directory
		$upload_dir = wp_upload_dir();
		$basedir    = $upload_dir['basedir'];

		if ( ! file_exists( $basedir ) ) {
			wp_mkdir_p( $basedir );
		}

		if ( file_exists( $basedir ) && is_writable( $basedir ) ) {
			$upload_htaccess = trailingslashit( $basedir ) . '.htaccess';
			$upload_content  = "# Block execution of PHP and executable scripts in uploads directory\n";
			$upload_content .= "<IfModule mod_rewrite.c>\n";
			$upload_content .= "RewriteEngine On\n";
			$upload_content .= "RewriteRule \.(?:php[0-9]*|pht|phtml|phps|phar)$ - [F,L,NC]\n";
			$upload_content .= "</IfModule>\n";

			file_put_contents( $upload_htaccess, $upload_content );
		}

		return $success;
	}

	/**
	 * Remove security rules from root .htaccess
	 *
	 * @return bool
	 */
	public static function remove_rules() {
		$root_htaccess = ABSPATH . '.htaccess';

		if ( file_exists( $root_htaccess ) && is_writable( $root_htaccess ) ) {
			$content = file_get_contents( $root_htaccess );
			$pattern = '/# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . '\n?/s';

			$cleaned = preg_replace( $pattern, '', $content );
			return ( false !== file_put_contents( $root_htaccess, ltrim( $cleaned ) ) );
		}

		return false;
	}

	/**
	 * Check if rules are active in root .htaccess
	 *
	 * @return bool
	 */
	public static function are_rules_active() {
		$root_htaccess = ABSPATH . '.htaccess';

		if ( file_exists( $root_htaccess ) ) {
			$content = file_get_contents( $root_htaccess );
			return ( strpos( $content, self::MARKER ) !== false );
		}

		return false;
	}

	/**
	 * Check if uploads .htaccess exists
	 *
	 * @return bool
	 */
	public static function is_uploads_protected() {
		$upload_dir      = wp_upload_dir();
		$upload_htaccess = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

		return file_exists( $upload_htaccess );
	}
}
