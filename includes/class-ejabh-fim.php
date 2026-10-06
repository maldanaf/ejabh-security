<?php
/**
 * File integrity monitoring.
 *
 * Signature scanning only finds malware it already has a pattern for. This does
 * the complementary job: it records a hash of every file and reports what
 * *changed* since last time. A brand-new PHP file in wp-content is suspicious
 * regardless of what it contains, and that is exactly the signal that would
 * have caught this site's compromise on day one.
 *
 * The baseline is captured during the normal file scan, so monitoring costs one
 * extra hash per file rather than a second walk of the disk.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Baseline capture and change detection.
 */
class Ejabh_FIM {

	const TABLE = 'dys_sec_baseline';

	/** Extensions treated as executable code for alerting purposes. */
	const CODE_EXT = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phar', 'phps', 'inc' );

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

		// path_key is a hash of the path: paths can exceed the 191-byte index
		// limit on utf8mb4, and we only ever look them up by exact match.
		dbDelta(
			"CREATE TABLE {$table} (
				path_key CHAR(40) NOT NULL,
				path TEXT NOT NULL,
				hash CHAR(32) NOT NULL,
				size BIGINT UNSIGNED NOT NULL DEFAULT 0,
				mtime BIGINT UNSIGNED NOT NULL DEFAULT 0,
				is_code TINYINT(1) NOT NULL DEFAULT 0,
				last_seen VARCHAR(32) NOT NULL DEFAULT '',
				PRIMARY KEY  (path_key),
				KEY last_seen (last_seen),
				KEY is_code (is_code)
			) {$charset};"
		);
	}

	/**
	 * Has a baseline ever been captured?
	 *
	 * @return bool
	 */
	public static function has_baseline() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) > 0;
	}

	/**
	 * Number of files in the baseline.
	 *
	 * @return int
	 */
	public static function count() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
	}

	/**
	 * Record one file and report how it differs from the baseline.
	 *
	 * @param string $rel     Site-relative path.
	 * @param string $hash    MD5 of the contents.
	 * @param int    $size    File size.
	 * @param int    $mtime   Modification time.
	 * @param string $scan_id Current scan identifier.
	 * @return string One of: 'new', 'modified', 'unchanged'.
	 */
	public static function record( $rel, $hash, $size, $mtime, $scan_id ) {
		global $wpdb;

		$table    = self::table();
		$path_key = sha1( $rel );
		$ext      = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
		$is_code  = in_array( $ext, self::CODE_EXT, true ) ? 1 : 0;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$existing = $wpdb->get_row( $wpdb->prepare( "SELECT hash FROM {$table} WHERE path_key = %s", $path_key ) );

		$status = 'unchanged';
		if ( ! $existing ) {
			$status = 'new';
		} elseif ( ! hash_equals( (string) $existing->hash, (string) $hash ) ) {
			$status = 'modified';
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (path_key, path, hash, size, mtime, is_code, last_seen)
				 VALUES (%s, %s, %s, %d, %d, %d, %s)
				 ON DUPLICATE KEY UPDATE hash = VALUES(hash), size = VALUES(size), mtime = VALUES(mtime), last_seen = VALUES(last_seen)",
				$path_key,
				$rel,
				$hash,
				(int) $size,
				(int) $mtime,
				$is_code,
				$scan_id
			)
		);

		return $status;
	}

	/**
	 * Files that were in the baseline but not seen in the latest scan.
	 *
	 * @param string $scan_id Current scan identifier.
	 * @return array Rows.
	 */
	public static function deleted_since( $scan_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results(
			$wpdb->prepare( "SELECT path, is_code FROM {$table} WHERE last_seen <> %s LIMIT 500", $scan_id )
		);
	}

	/**
	 * Drop rows for files that no longer exist.
	 *
	 * @param string $scan_id Current scan identifier.
	 * @return int Rows removed.
	 */
	public static function prune_missing( $scan_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE last_seen <> %s", $scan_id ) );
	}

	/**
	 * Wipe the baseline so the next scan re-establishes it.
	 *
	 * @return void
	 */
	public static function reset() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "TRUNCATE TABLE {$table}" );
		Ejabh_Logger::log( 'fim_reset', 'أُعيد ضبط خط الأساس لمراقبة الملفات.', 'warning' );
	}

	/**
	 * Turn a change into a finding, with severity based on what changed.
	 *
	 * A new PHP file is the headline case: it is how a backdoor arrives.
	 *
	 * @param string $status  new|modified.
	 * @param string $rel     Site-relative path.
	 * @param string $scan_id Scan identifier.
	 * @param int    $mtime   Modification time.
	 * @return bool Whether a finding was recorded.
	 */
	public static function report_change( $status, $rel, $scan_id, $mtime ) {
		$ext     = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
		$is_code = in_array( $ext, self::CODE_EXT, true );

		// Non-code churn (caches, logs, uploaded media) is noise.
		if ( ! $is_code ) {
			return false;
		}

		$when = $mtime ? gmdate( 'Y-m-d H:i', (int) $mtime ) . ' UTC' : __( 'غير معروف', 'ejabh-security' );

		if ( 'new' === $status ) {
			if ( ! Ejabh_Settings::get( 'fim_alert_new_php' ) ) {
				return false;
			}

			// A new PHP file under uploads has no legitimate explanation at all.
			$in_uploads = ( 0 === strpos( $rel, 'wp-content/uploads/' ) );

			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => $in_uploads ? 'critical' : 'high',
					'rule'      => 'fim_new_code_file',
					'title'     => __( 'ملف PHP جديد لم يكن موجوداً في الفحص السابق', 'ejabh-security' ),
					'target'    => $rel,
					'snippet'   => sprintf(
						/* translators: %s: modification date. */
						__( 'ظهر هذا الملف بعد آخر فحص. تاريخ آخر تعديل: %s. إن لم يكن ناتجاً عن تحديث إضافة أو قالب قمتم به، فهو مشبوه ويجب فتحه ومراجعته.', 'ejabh-security' ),
						$when
					),
				)
			);
			return true;
		}

		Ejabh_Findings::add(
			array(
				'scan_id'   => $scan_id,
				'scan_type' => 'file',
				'severity'  => 'high',
				'rule'      => 'fim_modified_code_file',
				'title'     => __( 'ملف PHP تغيّر محتواه منذ الفحص السابق', 'ejabh-security' ),
				'target'    => $rel,
				'snippet'   => sprintf(
					/* translators: %s: modification date. */
					__( 'تغيّرت بصمة هذا الملف. تاريخ آخر تعديل: %s. التغيّرات المتوقعة تأتي من تحديثات الإضافات والقوالب — أي تغيير خارج ذلك يستحق المراجعة.', 'ejabh-security' ),
					$when
				),
			)
		);

		return true;
	}

	/**
	 * Record findings for files that vanished.
	 *
	 * @param string $scan_id Scan identifier.
	 * @return int Number reported.
	 */
	public static function report_deletions( $scan_id ) {
		$rows  = self::deleted_since( $scan_id );
		$count = 0;

		foreach ( (array) $rows as $row ) {
			if ( ! $row->is_code ) {
				continue;
			}

			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => 'medium',
					'rule'      => 'fim_deleted_code_file',
					'title'     => __( 'ملف PHP كان موجوداً واختفى', 'ejabh-security' ),
					'target'    => $row->path,
					'snippet'   => __( 'حُذف هذا الملف منذ الفحص السابق. قد يكون تحديثاً عادياً، وقد يكون مخترقاً يمسح أثره أو سكانر استضافة حجَر ملفاً مصاباً.', 'ejabh-security' ),
				)
			);
			++$count;

			if ( $count >= 100 ) {
				break;
			}
		}

		return $count;
	}
}
