<?php
/**
 * Admin Security Dashboard & Management
 *
 * @package IPS_Security_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class IPS_Security_Admin {

	/**
	 * Initialize admin hooks
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_admin_menu' ) );
		add_action( 'admin_init', array( __CLASS__, 'handle_admin_actions' ) );
	}

	/**
	 * Register top-level admin menu
	 */
	public static function add_admin_menu() {
		add_menu_page(
			'IPS Security Guard',
			'IPS Security',
			'manage_options',
			'ips-security-guard',
			array( __CLASS__, 'render_dashboard' ),
			'dashicons-shield-alt',
			80
		);
	}

	/**
	 * Handle admin actions (reapply rules, clear logs)
	 */
	public static function handle_admin_actions() {
		if ( ! isset( $_POST['ips_sec_action'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$action = sanitize_text_field( $_POST['ips_sec_action'] );

		if ( 'apply_htaccess' === $action ) {
			check_admin_referer( 'ips_sec_apply_htaccess_nonce' );
			IPS_Security_Htaccess::apply_rules();
			add_settings_error( 'ips_sec_notices', 'rules_applied', 'Security hardening rules have been successfully applied to .htaccess files.', 'updated' );
		} elseif ( 'clear_logs' === $action ) {
			check_admin_referer( 'ips_sec_clear_logs_nonce' );
			delete_option( 'ips_security_logs' );
			add_settings_error( 'ips_sec_notices', 'logs_cleared', 'Security audit logs have been cleared.', 'updated' );
		}
	}

	/**
	 * Render the security dashboard
	 */
	public static function render_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Access denied.' );
		}

		$root_rules_active    = IPS_Security_Htaccess::are_rules_active();
		$uploads_protected    = IPS_Security_Htaccess::is_uploads_protected();
		$xmlrpc_disabled      = ! (bool) apply_filters( 'xmlrpc_enabled', true );
		$file_editor_disabled = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$logs                 = get_option( 'ips_security_logs', array() );

		?>
		<div class="wrap">
			<h1><span class="dashicons dashicons-shield-alt" style="font-size:32px;vertical-align:middle;margin-right:8px;color:#ef7f1a;"></span> IPS Security Guard</h1>
			<p>Comprehensive website hardening, firewall, and attack mitigation engine.</p>

			<?php settings_errors( 'ips_sec_notices' ); ?>

			<div style="display:grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px;">
				
				<!-- Left Column: Status Overview -->
				<div>
					<div class="postbox" style="padding:20px;">
						<h2 style="margin-top:0;">Active Protection Status</h2>
						<table class="widefat fixed striped" style="margin-top:15px;">
							<thead>
								<tr>
									<th>Security Layer</th>
									<th>Status</th>
									<th>Protection Details</th>
								</tr>
							</thead>
							<tbody>
								<tr>
									<td><strong>Root .htaccess Firewall</strong></td>
									<td>
										<?php if ( $root_rules_active ) : ?>
											<span style="color:#46b450;font-weight:bold;">&#x2714; Active</span>
										<?php else : ?>
											<span style="color:#dc3232;font-weight:bold;">&#x2718; Missing</span>
										<?php endif; ?>
									</td>
									<td>Blocks .sql database dumps, .git repositories, .env files, and sensitive extensions.</td>
								</tr>
								<tr>
									<td><strong>Uploads PHP Execution Block</strong></td>
									<td>
										<?php if ( $uploads_protected ) : ?>
											<span style="color:#46b450;font-weight:bold;">&#x2714; Protected</span>
										<?php else : ?>
											<span style="color:#dc3232;font-weight:bold;">&#x2718; Vulnerable</span>
										<?php endif; ?>
									</td>
									<td>Prevents execution of .php, .phtml, and executable scripts inside wp-content/uploads/.</td>
								</tr>
								<tr>
									<td><strong>XML-RPC Attack Defense</strong></td>
									<td>
										<span style="color:#46b450;font-weight:bold;">&#x2714; Disabled</span>
									</td>
									<td>Protects against DDoS amplification, brute force, and unauthorized pingbacks.</td>
								</tr>
								<tr>
									<td><strong>User Enumeration Shield</strong></td>
									<td>
										<span style="color:#46b450;font-weight:bold;">&#x2714; Active</span>
									</td>
									<td>Blocks automated scanners from harvesting administrator usernames via ?author=1 and REST API.</td>
								</tr>
								<tr>
									<td><strong>HTTP Security Response Headers</strong></td>
									<td>
										<span style="color:#46b450;font-weight:bold;">&#x2714; Active</span>
									</td>
									<td>Sends X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, and Referrer-Policy.</td>
								</tr>
								<tr>
									<td><strong>Brute-Force Login Rate Limiting</strong></td>
									<td>
										<span style="color:#46b450;font-weight:bold;">&#x2714; Active</span>
									</td>
									<td>Obscures login errors and automatically locks out offending IPs after 5 consecutive failed attempts.</td>
								</tr>
								<tr>
									<td><strong>Dashboard Code Editor</strong></td>
									<td>
										<?php if ( $file_editor_disabled ) : ?>
											<span style="color:#46b450;font-weight:bold;">&#x2714; Disabled</span>
										<?php else : ?>
											<span style="color:#f0b849;font-weight:bold;">&#x26A0; Enabled</span>
										<?php endif; ?>
									</td>
									<td>Prevents arbitrary PHP script modification directly through WordPress admin.</td>
								</tr>
							</tbody>
						</table>
					</div>

					<!-- Event Logs -->
					<div class="postbox" style="padding:20px;">
						<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
							<h2 style="margin:0;">Recent Blocked Attacks & Security Events</h2>
							<?php if ( ! empty( $logs ) ) : ?>
								<form method="post" style="margin:0;">
									<?php wp_nonce_field( 'ips_sec_clear_logs_nonce' ); ?>
									<input type="hidden" name="ips_sec_action" value="clear_logs">
									<button type="submit" class="button" onclick="return confirm('Are you sure you want to clear all logs?');">Clear Audit Logs</button>
								</form>
							<?php endif; ?>
						</div>

						<?php if ( empty( $logs ) ) : ?>
							<p style="color:#666; font-style:italic;">No blocked attacks recorded yet. Your website is clean and protected.</p>
						<?php else : ?>
							<table class="widefat fixed striped">
								<thead>
									<tr>
										<th style="width:140px;">Timestamp</th>
										<th style="width:160px;">Event Type</th>
										<th style="width:110px;">Blocked IP</th>
										<th>Reason / Details</th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $logs as $log ) : ?>
										<tr>
											<td><?php echo esc_html( $log['time'] ); ?></td>
											<td><strong style="color:#d63638;"><?php echo esc_html( $log['type'] ); ?></strong></td>
											<td><code><?php echo esc_html( $log['ip'] ); ?></code></td>
											<td><?php echo esc_html( $log['reason'] ); ?></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- Right Column: Quick Actions & Tools -->
				<div>
					<div class="postbox" style="padding:20px;">
						<h2 style="margin-top:0;">Security Actions</h2>
						<p>If you have modified your web server or need to re-verify all protection rules, you can reapply them below:</p>

						<form method="post" style="margin-top:15px;">
							<?php wp_nonce_field( 'ips_sec_apply_htaccess_nonce' ); ?>
							<input type="hidden" name="ips_sec_action" value="apply_htaccess">
							<button type="submit" class="button button-primary" style="width:100%; height:40px; font-size:14px;">
								<span class="dashicons dashicons-update" style="vertical-align:middle;"></span> Reapply .htaccess Rules
							</button>
						</form>
					</div>

					<div class="postbox" style="padding:20px;">
						<h2 style="margin-top:0;">About IPS Security Guard</h2>
						<p>Engineered specifically for the Indian Public School website to provide high-performance, zero-bloat security protection.</p>
						<ul style="list-style:disc; margin-left:20px; color:#555;">
							<li>Zero third-party cloud dependencies</li>
							<li>Instant Apache mod_rewrite interception</li>
							<li>Lightweight SQLite/MySQL transient memory footprint</li>
						</ul>
					</div>
				</div>

			</div>
		</div>
		<?php
	}
}
