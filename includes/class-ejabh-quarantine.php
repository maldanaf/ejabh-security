<?php
/**
 * Quarantine.
 *
 * Deleting a suspected file is irreversible, and automated malware removal gets
 * it wrong often enough that an undo path matters. Quarantining moves the file
 * somewhere it cannot execute or be reached over HTTP, records where it came
 * from, and keeps a copy so a false positive can be undone.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Isolates suspicious files instead of destroying them.
 */
class Ejabh_Quarantine {

	const TABLE = 'dys_sec_quarantine';

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
				original_path TEXT NOT NULL,
				stored_name VARCHAR(255) NOT NULL,
				size BIGINT UNSIGNED NOT NULL DEFAULT 0,
				hash CHAR(32) NOT NULL DEFAULT '',
				reason TEXT NULL,
				quarantined_at DATETIME NOT NULL,
				restored_at DATETIME NULL,
				PRIMARY KEY  (id),
				KEY quarantined_at (quarantined_at)
			) {$charset};"
		);
	}

	/**
	 * The quarantine directory, created and locked down on demand.
	 *
	 * @return string
	 */
	public static function dir() {
		$dir = WP_CONTENT_DIR . '/dys-quarantine';

		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$htaccess,
				"<IfModule authz_core_module>\n\tRequire all denied\n</IfModule>\n"
				. "<IfModule !authz_core_module>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n"
				. "<IfModule mod_php.c>\n\tphp_flag engine off\n</IfModule>\n"
				. "Options -Indexes\n"
			);
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}

		return $dir;
	}

	/**
	 * Move a file into quarantine.
	 *
	 * @param string $abs_path Absolute path to the file.
	 * @param string $reason   Why it was isolated.
	 * @return array {ok, msg}
	 */
	public static function capture( $abs_path, $reason = '' ) {
		global $wpdb;

		$real = realpath( $abs_path );
		$root = realpath( ABSPATH );

		if ( ! $real || ! is_file( $real ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'الملف غير موجود.', 'ejabh-security' ),
			);
		}

		// Refuse anything outside the site, and refuse to quarantine ourselves.
		if ( ! $root || 0 !== strpos( wp_normalize_path( $real ), trailingslashit( wp_normalize_path( $root ) ) ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'الملف خارج مجلد الموقع — رُفضت العملية.', 'ejabh-security' ),
			);
		}

		$self = realpath( EJABH_SEC_DIR );
		if ( $self && 0 === strpos( wp_normalize_path( $real ), trailingslashit( wp_normalize_path( $self ) ) ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'لا يمكن حجر ملفات إضافة الحماية نفسها.', 'ejabh-security' ),
			);
		}

		// Never quarantine the things the site cannot boot without.
		$rel       = Ejabh_Core_Integrity::relative( $real );
		$protected = array( 'wp-config.php', 'index.php', 'wp-load.php', 'wp-settings.php', 'wp-blog-header.php', '.htaccess' );
		if ( in_array( $rel, $protected, true ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'هذا ملف أساسي لعمل الموقع ولا يجوز حجره.', 'ejabh-security' ),
			);
		}

		$size = (int) filesize( $real );
		$hash = (string) @md5_file( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$stored = gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 10, false, false ) . '.quarantined';
		$dest   = self::dir() . '/' . $stored;

		if ( ! @rename( $real, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			// rename() fails across filesystems; fall back to copy + unlink.
			if ( ! @copy( $real, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				return array(
					'ok'  => false,
					'msg' => __( 'تعذّر نقل الملف إلى الحجر — تحقق من الصلاحيات.', 'ejabh-security' ),
				);
			}
			@unlink( $real ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			self::table(),
			array(
				'original_path'  => $rel,
				'stored_name'    => $stored,
				'size'           => $size,
				'hash'           => $hash,
				'reason'         => $reason,
				'quarantined_at' => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s' )
		);

		Ejabh_Logger::log(
			'file_quarantined',
			sprintf( 'حُجر الملف %s (%s). السبب: %s', $rel, size_format( $size ), $reason ? $reason : '—' ),
			'critical'
		);

		return array(
			'ok'  => true,
			'msg' => sprintf(
				/* translators: %s: relative file path. */
				__( 'نُقل %s إلى الحجر الصحي. يمكنك استعادته إن تبيّن أنه سليم.', 'ejabh-security' ),
				$rel
			),
		);
	}

	/**
	 * Put a quarantined file back where it came from.
	 *
	 * @param int $id Quarantine row ID.
	 * @return array {ok, msg}
	 */
	public static function restore( $id ) {
		global $wpdb;

		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", (int) $id ) );

		if ( ! $row || $row->restored_at ) {
			return array(
				'ok'  => false,
				'msg' => __( 'السجل غير موجود أو استُعيد مسبقاً.', 'ejabh-security' ),
			);
		}

		$source = self::dir() . '/' . $row->stored_name;
		if ( ! file_exists( $source ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'الملف المحجوز غير موجود على القرص.', 'ejabh-security' ),
			);
		}

		// Rebuild the destination from the stored relative path, and make sure it
		// still resolves inside the site.
		$rel  = ltrim( str_replace( array( '..', '\\' ), array( '', '/' ), (string) $row->original_path ), '/' );
		$dest = ABSPATH . $rel;
		$root = trailingslashit( wp_normalize_path( realpath( ABSPATH ) ) );

		if ( 0 !== strpos( wp_normalize_path( $dest ), $root ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'مسار الاستعادة غير صالح.', 'ejabh-security' ),
			);
		}

		$parent = dirname( $dest );
		if ( ! is_dir( $parent ) ) {
			wp_mkdir_p( $parent );
		}

		// The watcher may have left an inert placeholder in the file's place.
		if ( file_exists( $dest ) && Ejabh_Watcher::is_stub( (string) @file_get_contents( $dest, false, null, 0, 400 ) ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
			@unlink( $dest ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged
		}

		if ( file_exists( $dest ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'يوجد ملف بنفس الاسم في المكان الأصلي. احذفه أو انقله أولاً.', 'ejabh-security' ),
			);
		}

		if ( ! @rename( $source, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( ! @copy( $source, $dest ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				return array(
					'ok'  => false,
					'msg' => __( 'تعذّرت استعادة الملف.', 'ejabh-security' ),
				);
			}
			@unlink( $source ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->update( $table, array( 'restored_at' => current_time( 'mysql', true ) ), array( 'id' => (int) $id ), array( '%s' ), array( '%d' ) );

		Ejabh_Logger::log( 'file_restored', sprintf( 'استُعيد الملف المحجوز %s.', $rel ), 'warning' );

		return array(
			'ok'  => true,
			'msg' => sprintf(
				/* translators: %s: relative file path. */
				__( 'استُعيد %s إلى مكانه الأصلي.', 'ejabh-security' ),
				$rel
			),
		);
	}

	/**
	 * Permanently delete a quarantined file.
	 *
	 * @param int $id Quarantine row ID.
	 * @return array {ok, msg}
	 */
	public static function purge( $id ) {
		global $wpdb;

		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", (int) $id ) );

		if ( ! $row ) {
			return array(
				'ok'  => false,
				'msg' => __( 'السجل غير موجود.', 'ejabh-security' ),
			);
		}

		$file = self::dir() . '/' . $row->stored_name;
		if ( file_exists( $file ) ) {
			@unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->delete( $table, array( 'id' => (int) $id ), array( '%d' ) );

		Ejabh_Logger::log( 'quarantine_purged', sprintf( 'حُذف نهائياً الملف المحجوز %s.', $row->original_path ), 'warning' );

		return array(
			'ok'  => true,
			'msg' => __( 'حُذف الملف نهائياً.', 'ejabh-security' ),
		);
	}

	/**
	 * Quarantine rows for the admin screen.
	 *
	 * @param int $limit Max rows.
	 * @return array
	 */
	public static function all( $limit = 200 ) {
		global $wpdb;
		$table = self::table();
		$limit = max( 1, min( 500, (int) $limit ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit ) );
	}

	/**
	 * Count of files currently held.
	 *
	 * @return int
	 */
	public static function held_count() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE restored_at IS NULL" );
	}
}
