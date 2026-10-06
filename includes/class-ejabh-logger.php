<?php
/**
 * Security event log.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Append-only audit trail for everything the plugin does or blocks.
 */
class Ejabh_Logger {

	/**
	 * Table name (without prefix).
	 */
	const TABLE = 'dys_sec_log';

	/**
	 * Fully qualified table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	/**
	 * Create the table.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$table   = self::table();

		dbDelta(
			"CREATE TABLE {$table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				created_at DATETIME NOT NULL,
				severity VARCHAR(12) NOT NULL DEFAULT 'info',
				event VARCHAR(64) NOT NULL,
				user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
				ip VARCHAR(45) NOT NULL DEFAULT '',
				message TEXT NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY event (event),
				KEY severity (severity)
			) {$charset};"
		);
	}

	/**
	 * Record an event.
	 *
	 * @param string $event    Machine-readable event slug.
	 * @param string $message  Human-readable detail.
	 * @param string $severity info|warning|critical.
	 * @param int    $user_id  Related user, 0 for none.
	 * @return void
	 */
	public static function log( $event, $message = '', $severity = 'info', $user_id = 0 ) {
		global $wpdb;

		if ( ! $user_id && function_exists( 'get_current_user_id' ) ) {
			$user_id = get_current_user_id();
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			self::table(),
			array(
				'created_at' => current_time( 'mysql', true ),
				'severity'   => substr( $severity, 0, 12 ),
				'event'      => substr( $event, 0, 64 ),
				'user_id'    => (int) $user_id,
				'ip'         => self::client_ip(),
				'message'    => $message,
			),
			array( '%s', '%s', '%s', '%d', '%s', '%s' )
		);

		if ( 'critical' === $severity && Ejabh_Settings::get( 'notify_on_critical' ) ) {
			Ejabh_Mailer::notify_critical( $event, $message );
		}
	}

	/**
	 * Read recent log rows.
	 *
	 * @param int    $limit    Max rows.
	 * @param string $severity Optional severity filter.
	 * @return array
	 */
	public static function recent( $limit = 100, $severity = '' ) {
		global $wpdb;
		$table = self::table();
		$limit = max( 1, min( 1000, (int) $limit ) );

		if ( $severity ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE severity = %s ORDER BY id DESC LIMIT %d", $severity, $limit ) );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit ) );
	}

	/**
	 * Delete log rows older than N days.
	 *
	 * @param int $days Retention window.
	 * @return void
	 */
	public static function prune( $days = 90 ) {
		global $wpdb;
		$table  = self::table();
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( (int) $days * DAY_IN_SECONDS ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $cutoff ) );
	}

	/**
	 * Best-effort client IP.
	 *
	 * Only REMOTE_ADDR is trusted by default; proxy headers are spoofable and
	 * are therefore recorded separately rather than used as the identity.
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );
		return $ip ? $ip : '';
	}

	/**
	 * Truncated user agent string.
	 *
	 * @return string
	 */
	public static function client_ua() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		return substr( sanitize_text_field( $ua ), 0, 255 );
	}
}
