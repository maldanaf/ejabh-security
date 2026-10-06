<?php
/**
 * Scan findings storage.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Stores what the file and database scanners discovered.
 */
class Ejabh_Findings {

	const TABLE = 'dys_sec_findings';

	/** Severity ranks used for sorting. */
	const RANK = array(
		'critical' => 4,
		'high'     => 3,
		'medium'   => 2,
		'low'      => 1,
	);

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
				scan_id VARCHAR(32) NOT NULL,
				scan_type VARCHAR(10) NOT NULL,
				severity VARCHAR(10) NOT NULL,
				rule VARCHAR(64) NOT NULL,
				title VARCHAR(255) NOT NULL,
				target TEXT NOT NULL,
				line_no INT UNSIGNED NOT NULL DEFAULT 0,
				snippet TEXT NULL,
				action VARCHAR(12) NOT NULL DEFAULT 'review',
				remediation TEXT NULL,
				status VARCHAR(12) NOT NULL DEFAULT 'open',
				created_at DATETIME NOT NULL,
				PRIMARY KEY  (id),
				KEY scan_id (scan_id),
				KEY scan_type (scan_type),
				KEY severity (severity),
				KEY status (status)
			) {$charset};"
		);
	}

	/**
	 * Record a finding.
	 *
	 * @param array $args Finding fields.
	 * @return void
	 */
	public static function add( array $args ) {
		global $wpdb;

		$args = wp_parse_args(
			$args,
			array(
				'scan_id'   => '',
				'scan_type' => 'file',
				'severity'  => 'medium',
				'rule'      => '',
				'title'     => '',
				'target'    => '',
				'line_no'   => 0,
				'snippet'   => '',
			)
		);

		// Keep snippets short so a minified payload cannot blow up the table.
		$snippet = (string) $args['snippet'];
		if ( strlen( $snippet ) > 1200 ) {
			$snippet = substr( $snippet, 0, 1200 ) . ' …';
		}

		// Every finding carries the instruction for what to do about it.
		$fix = Ejabh_Signatures::remediation_for( $args['rule'], $args['severity'] );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			self::table(),
			array(
				'scan_id'     => substr( $args['scan_id'], 0, 32 ),
				'scan_type'   => substr( $args['scan_type'], 0, 10 ),
				'severity'    => substr( $args['severity'], 0, 10 ),
				'rule'        => substr( $args['rule'], 0, 64 ),
				'title'       => substr( $args['title'], 0, 255 ),
				'target'      => $args['target'],
				'line_no'     => (int) $args['line_no'],
				'snippet'     => $snippet,
				'action'      => $fix['action'],
				'remediation' => $fix['text'],
				'status'      => 'open',
				'created_at'  => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Delete every finding, of every type.
	 *
	 * @return int Rows removed.
	 */
	public static function clear_all() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query( "DELETE FROM {$table}" );
	}

	/**
	 * Count findings grouped by recommended action.
	 *
	 * @param string $scan_type Optional filter.
	 * @return array Action => count.
	 */
	public static function action_counts( $scan_type = '' ) {
		global $wpdb;
		$table = self::table();

		if ( $scan_type ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT action, COUNT(*) AS c FROM {$table} WHERE scan_type = %s AND status = 'open' GROUP BY action", $scan_type ) );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT action, COUNT(*) AS c FROM {$table} WHERE status = 'open' GROUP BY action" );
		}

		$out = array();
		foreach ( (array) $rows as $row ) {
			$out[ $row->action ] = (int) $row->c;
		}
		return $out;
	}

	/**
	 * Delete every finding for a scan type (used when a new scan starts).
	 *
	 * @param string $scan_type file|db.
	 * @return void
	 */
	public static function clear_type( $scan_type ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE scan_type = %s", $scan_type ) );
	}

	/**
	 * Fetch findings, most severe first.
	 *
	 * @param string $scan_type file|db|'' for both.
	 * @param int    $limit     Max rows.
	 * @return array
	 */
	public static function get( $scan_type = '', $limit = 500 ) {
		global $wpdb;
		$table = self::table();
		$limit = max( 1, min( 2000, (int) $limit ) );

		$order = "FIELD(severity,'critical','high','medium','low'), id ASC";

		if ( $scan_type ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE scan_type = %s ORDER BY {$order} LIMIT %d", $scan_type, $limit ) );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY {$order} LIMIT %d", $limit ) );
	}

	/**
	 * Count findings grouped by severity.
	 *
	 * @param string $scan_type file|db|'' for both.
	 * @return array Severity => count.
	 */
	public static function counts( $scan_type = '' ) {
		global $wpdb;
		$table = self::table();
		$out   = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
		);

		if ( $scan_type ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT severity, COUNT(*) AS c FROM {$table} WHERE scan_type = %s GROUP BY severity", $scan_type ) );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT severity, COUNT(*) AS c FROM {$table} GROUP BY severity" );
		}

		foreach ( (array) $rows as $row ) {
			if ( isset( $out[ $row->severity ] ) ) {
				$out[ $row->severity ] = (int) $row->c;
			}
		}
		return $out;
	}

	/**
	 * Mark a finding as reviewed so it stops shouting.
	 *
	 * @param int    $id     Finding ID.
	 * @param string $status open|ignored|resolved.
	 * @return void
	 */
	public static function set_status( $id, $status ) {
		global $wpdb;
		if ( ! in_array( $status, array( 'open', 'ignored', 'resolved' ), true ) ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->update( self::table(), array( 'status' => $status ), array( 'id' => (int) $id ), array( '%s' ), array( '%d' ) );
	}
}
