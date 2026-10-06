<?php
/**
 * Settings store.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Reads and writes the single options array used by the whole plugin.
 */
class Ejabh_Settings {

	const OPTION = 'dys_sec_settings';

	/** Upper bound on alert recipients; each one is a separate wp_mail(). */
	const MAX_RECIPIENTS = 20;

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Default values for every setting.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			// Two-factor authentication.
			'2fa_enabled'          => 1,
			'2fa_code_length'      => 6,
			'2fa_code_ttl'         => 600,   // Seconds a code stays valid.
			'2fa_max_attempts'     => 5,     // Wrong codes before the pending login dies.
			'2fa_resend_wait'      => 60,    // Seconds between resend requests.
			'2fa_exempt_user_ids'  => array(),
			'2fa_fail_open'        => 0,     // 1 = let the user in when wp_mail() fails.
			'2fa_block_xmlrpc'     => 1,     // Kill XML-RPC authentication (bypasses 2FA).
			'2fa_block_app_pw'     => 1,     // Kill application passwords (bypass 2FA).

			// Plugin guard.
			'guard_enabled'        => 1,
			'guard_autodelete'     => 1,
			'guard_blocked_slugs'  => array(
				'wp-file-manager',
				'wp-file-manager-pro',
				'file-manager',
				'file-manager-advanced',
				'filemanager',
				'wp-filemanager',
				'advanced-file-manager',
				'file-manager-pro',
				'wp-file-download',
				'nested-pages-file-manager',
				'wp-security-audit-log-file-manager',
			),
			'guard_blocked_files'  => array(
				'file_folder_manager.php',
				'wp-file-manager.php',
				'elFinderConnector.class.php',
			),

			// Capability lockdown.
			'caps_enabled'         => 1,
			'caps_owner_id'        => 0,
			'caps_lock_plugins'    => 1,
			'caps_lock_themes'     => 1,
			'caps_lock_file_edit'  => 1,

			// Scanners.
			'scan_max_file_size'   => 3145728, // 3 MB — bigger files are hashed, not regexed.
			'scan_skip_dirs'       => array( 'node_modules', '.git', '.svn', 'wp-content/cache', 'wp-content/ai1wm-backups', 'wp-content/upgrade', 'wp-content/uploads/wp-file-manager-pro' ),
			'scan_time_budget'     => 12,      // Seconds of work per AJAX batch.

			// Plugin/theme integrity audit.
			'integrity_enabled'    => 1,

			// File integrity monitoring.
			'fim_enabled'          => 1,
			'fim_alert_new_php'    => 1,

			// Administrator creation lockdown.
			'admin_guard_enabled'  => 1,
			'admin_guard_revert'   => 1,

			// Login rate limiting.
			'login_limit_enabled'  => 1,
			'login_max_attempts'   => 5,
			'login_lockout_mins'   => 30,
			'login_window_mins'    => 15,
			'login_ip_allowlist'   => array(),

			// New-location login alerts.
			'new_ip_alert_enabled' => 1,
			'new_ip_alert_roles'   => array( 'administrator', 'editor', 'shop_manager' ),

			// User enumeration.
			'enum_block_enabled'   => 1,

			// Quarantine.
			'quarantine_enabled'   => 1,

			// Scheduled scans.
			'sched_scan_enabled'   => 1,
			'sched_scan_freq'      => 'daily',

			// Admin experience.
			'clean_admin_enabled'  => 1,

			// WordPress 6.9+ Abilities API: require sign-in to run abilities over REST.
			'abilities_require_login' => 1,

			// Real-time protection.
			'upload_guard_enabled' => 1,       // Inspect $_FILES before any plugin sees them.
			'watch_enabled'        => 1,       // Five-minute sweep for newly planted files.
			'watch_action'         => 'quarantine', // quarantine|neutralize|report.

			// Notifications.
			'notify_email'         => '',      // Pre-2.0 single address; read only as a fallback.
			'notify_emails'        => array(), // Everyone who receives alerts and the daily report.
			'notify_on_critical'   => 1,
			'report_daily_enabled' => 1,
			'report_daily_hour'    => 8,       // Site-local hour the daily report goes out.

			// Updates from GitHub Releases (signature-verified).
			'auto_update_self'     => 1,
		);
	}

	/**
	 * Get all settings merged over defaults.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored     = get_option( self::OPTION, array() );
			$stored     = is_array( $stored ) ? $stored : array();
			self::$cache = array_merge( self::defaults(), $stored );
		}
		return self::$cache;
	}

	/**
	 * Get one setting.
	 *
	 * @param string $key     Setting key.
	 * @param mixed  $default Fallback when the key is unknown.
	 * @return mixed
	 */
	public static function get( $key, $default = null ) {
		$all = self::all();
		if ( array_key_exists( $key, $all ) ) {
			return $all[ $key ];
		}
		return $default;
	}

	/**
	 * Persist a set of settings.
	 *
	 * @param array $values Key/value pairs to merge in.
	 * @return void
	 */
	public static function update( array $values ) {
		$all = array_merge( self::all(), $values );
		// Only keep known keys so a stray POST field cannot pollute the option.
		$all = array_intersect_key( $all, self::defaults() );
		update_option( self::OPTION, $all, false );
		self::$cache = null;
	}

	/**
	 * The user ID allowed to manage plugins/themes.
	 *
	 * Falls back to the lowest-ID administrator so the site can never end up
	 * with nobody able to manage plugins.
	 *
	 * @return int
	 */
	public static function owner_id() {
		// Memoised: this is consulted on every capability check, and the
		// fallback path runs a user query.
		static $resolved = null;

		if ( null !== $resolved ) {
			return $resolved;
		}

		$id = (int) self::get( 'caps_owner_id' );
		if ( $id > 0 && get_userdata( $id ) ) {
			$resolved = $id;
			return $resolved;
		}

		$resolved = self::first_admin_id();
		return $resolved;
	}

	/**
	 * Lowest-ID administrator on the site.
	 *
	 * @return int
	 */
	public static function first_admin_id() {
		$admins = get_users(
			array(
				'role'    => 'administrator',
				'orderby' => 'ID',
				'order'   => 'ASC',
				'number'  => 1,
				'fields'  => 'ID',
			)
		);
		return $admins ? (int) $admins[0] : 0;
	}

	/**
	 * Everyone who receives security mail.
	 *
	 * Falls back to the pre-2.0 single address, then to the site admin e-mail,
	 * so upgrading never silences alerts.
	 *
	 * @return string[]
	 */
	public static function notify_recipients() {
		$list = array();
		foreach ( (array) self::get( 'notify_emails' ) as $email ) {
			$email = trim( (string) $email );
			if ( $email && is_email( $email ) ) {
				$list[] = strtolower( $email );
			}
		}

		if ( ! $list ) {
			$legacy = trim( (string) self::get( 'notify_email' ) );
			$list[] = ( $legacy && is_email( $legacy ) ) ? $legacy : (string) get_option( 'admin_email' );
		}

		return array_values( array_unique( array_filter( $list ) ) );
	}

	/**
	 * Parse free text into a clean list of addresses.
	 *
	 * Accepts one per line, or separated by commas, semicolons or spaces.
	 *
	 * @param string $raw     User input.
	 * @param array  $invalid Receives the entries that were not addresses.
	 * @return string[]
	 */
	public static function parse_email_list( $raw, &$invalid = array() ) {
		$invalid = array();
		$out     = array();

		foreach ( (array) preg_split( '/[\s,;]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY ) as $part ) {
			$email = sanitize_email( $part );
			if ( $email && is_email( $email ) ) {
				$out[] = strtolower( $email );
			} else {
				$invalid[] = $part;
			}
		}

		return array_slice( array_values( array_unique( $out ) ), 0, self::MAX_RECIPIENTS );
	}
}
