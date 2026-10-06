<?php
/**
 * File-manager plugin guard.
 *
 * File-manager plugins expose a filesystem browser with upload and edit powers
 * to whoever can reach it, and the popular ones have a history of unauthenticated
 * remote code execution. This class denies them at every layer:
 *
 *  - they are stripped from the active plugin list *as it is read*, so even a
 *    direct database write cannot get them loaded;
 *  - installation and activation are refused;
 *  - they are hidden from the plugin directory search results;
 *  - a sweep deletes their directories on sight, on every admin request and on
 *    a schedule, so an upload over FTP or through a shell does not survive.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Blocks and removes file-manager plugins.
 */
class Ejabh_Plugin_Guard {

	/** Cron hook for the periodic sweep. */
	const CRON_HOOK = 'dys_sec_guard_sweep';

	/**
	 * Blocked plugins seen during this request, pending a log entry.
	 *
	 * @var array
	 */
	private $pending_log = array();

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Ejabh_Settings::get( 'guard_enabled' ) ) {
			return;
		}

		// Never let a blocked plugin be loaded, whatever the option says.
		// This filter fires from wp-settings.php before pluggable.php exists, so
		// it must not log (logging can send mail). Findings are flushed on init.
		add_filter( 'option_active_plugins', array( $this, 'filter_active_plugins' ), 1 );
		add_action( 'init', array( $this, 'flush_log' ), 1 );
		add_filter( 'pre_update_option_active_plugins', array( $this, 'filter_active_plugins' ), 1 );
		add_filter( 'site_option_active_sitewide_plugins', array( $this, 'filter_sitewide_plugins' ), 1 );

		// Refuse installation and activation.
		add_filter( 'upgrader_source_selection', array( $this, 'block_install' ), 1, 4 );
		add_action( 'activated_plugin', array( $this, 'undo_activation' ), 1 );

		// Hide them from the plugin browser.
		add_filter( 'plugins_api_result', array( $this, 'filter_api_results' ), 10, 3 );

		// Sweep the filesystem.
		add_action( 'admin_init', array( $this, 'maybe_sweep' ) );
		add_action( self::CRON_HOOK, array( $this, 'sweep' ) );
		add_action( 'upgrader_process_complete', array( $this, 'sweep' ), 20 );
	}

	/**
	 * The blocked slug list, normalised.
	 *
	 * @return array
	 */
	public static function blocked_slugs() {
		$slugs = (array) Ejabh_Settings::get( 'guard_blocked_slugs' );
		$slugs = array_map( 'strtolower', array_map( 'trim', $slugs ) );
		$slugs = array_filter( $slugs );

		// Guard against a configuration that would delete this plugin.
		$self = strtolower( dirname( EJABH_SEC_BASENAME ) );
		$slugs = array_diff( $slugs, array( $self ) );

		return array_values( array_unique( $slugs ) );
	}

	/**
	 * Blocked bare filenames, normalised.
	 *
	 * @return array
	 */
	public static function blocked_files() {
		$files = (array) Ejabh_Settings::get( 'guard_blocked_files' );
		$files = array_map( 'strtolower', array_map( 'trim', $files ) );
		return array_values( array_unique( array_filter( $files ) ) );
	}

	/**
	 * Is this plugin path (e.g. "wp-file-manager/file_folder_manager.php") blocked?
	 *
	 * @param string $plugin_file Plugin path relative to the plugins directory.
	 * @return bool
	 */
	public static function is_blocked( $plugin_file ) {
		$plugin_file = (string) $plugin_file;
		$slug        = strtolower( strtok( $plugin_file, '/' ) );

		if ( in_array( $slug, self::blocked_slugs(), true ) ) {
			return true;
		}

		$basename = strtolower( basename( $plugin_file ) );
		return in_array( $basename, self::blocked_files(), true );
	}

	/**
	 * Strip blocked plugins from the active list.
	 *
	 * @param mixed $plugins Active plugin list.
	 * @return mixed
	 */
	public function filter_active_plugins( $plugins ) {
		if ( ! is_array( $plugins ) ) {
			return $plugins;
		}

		$kept    = array();
		$removed = array();

		foreach ( $plugins as $plugin ) {
			if ( self::is_blocked( $plugin ) ) {
				$removed[] = $plugin;
				continue;
			}
			$kept[] = $plugin;
		}

		// Queue for logging rather than logging here: this filter runs before
		// pluggable.php is loaded, and it runs on every read of the option.
		foreach ( $removed as $plugin ) {
			$this->pending_log[ $plugin ] = true;
		}

		return array_values( $kept );
	}

	/**
	 * Write queued detections to the log, once WordPress is fully loaded.
	 *
	 * @return void
	 */
	public function flush_log() {
		if ( ! $this->pending_log ) {
			return;
		}

		foreach ( array_keys( $this->pending_log ) as $plugin ) {
			Ejabh_Logger::log(
				'guard_blocked_load',
				sprintf( 'مُنِع تحميل إضافة محظورة: %s', $plugin ),
				'critical'
			);
		}

		$this->pending_log = array();
	}

	/**
	 * Strip blocked plugins from the network-activated list.
	 *
	 * @param mixed $plugins Sitewide plugin map (plugin file => timestamp).
	 * @return mixed
	 */
	public function filter_sitewide_plugins( $plugins ) {
		if ( ! is_array( $plugins ) ) {
			return $plugins;
		}
		foreach ( array_keys( $plugins ) as $plugin ) {
			if ( self::is_blocked( $plugin ) ) {
				unset( $plugins[ $plugin ] );
			}
		}
		return $plugins;
	}

	/**
	 * Refuse to install a blocked plugin.
	 *
	 * @param string|WP_Error $source        Path to the unpacked package.
	 * @param string          $remote_source Path to the downloaded archive.
	 * @param WP_Upgrader     $upgrader      Upgrader instance.
	 * @param array           $hook_extra    Extra arguments.
	 * @return string|WP_Error
	 */
	public function block_install( $source, $remote_source = '', $upgrader = null, $hook_extra = array() ) {
		if ( is_wp_error( $source ) ) {
			return $source;
		}

		$candidates = array( basename( untrailingslashit( (string) $source ) ) );

		if ( ! empty( $hook_extra['plugin'] ) ) {
			$candidates[] = strtok( (string) $hook_extra['plugin'], '/' );
		}

		$blocked = self::blocked_slugs();

		foreach ( $candidates as $slug ) {
			if ( in_array( strtolower( $slug ), $blocked, true ) ) {
				Ejabh_Logger::log(
					'guard_blocked_install',
					sprintf( 'مُنِع تثبيت إضافة محظورة: %s', $slug ),
					'critical'
				);
				return new WP_Error(
					'dys_sec_blocked_plugin',
					sprintf(
						/* translators: %s: plugin slug. */
						__( 'إضافة "%s" محظورة على هذا الموقع بواسطة Ejabh Security. إضافات مدير الملفات تمنح صلاحية قراءة وكتابة كل ملفات السيرفر، وهي من أكثر الطرق استغلالاً لاختراق مواقع ووردبريس. لتثبيتها اضطراراً، أزلها من قائمة الحظر في إعدادات الإضافة أولاً.', 'ejabh-security' ),
						$slug
					)
				);
			}
		}

		// Also refuse an archive whose main file matches a blocked filename.
		$files = self::blocked_files();
		if ( $files && is_dir( $source ) ) {
			foreach ( (array) @scandir( $source ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( in_array( strtolower( (string) $entry ), $files, true ) ) {
					Ejabh_Logger::log(
						'guard_blocked_install',
						sprintf( 'مُنِع تثبيت حزمة تحتوي ملفاً محظوراً: %s', $entry ),
						'critical'
					);
					return new WP_Error(
						'dys_sec_blocked_plugin',
						__( 'هذه الحزمة تحتوي على ملف مدير ملفات محظور على هذا الموقع.', 'ejabh-security' )
					);
				}
			}
		}

		return $source;
	}

	/**
	 * If a blocked plugin somehow got activated, undo it at once.
	 *
	 * @param string $plugin Plugin file.
	 * @return void
	 */
	public function undo_activation( $plugin ) {
		if ( ! self::is_blocked( $plugin ) ) {
			return;
		}

		deactivate_plugins( $plugin, true );

		Ejabh_Logger::log(
			'guard_blocked_activation',
			sprintf( 'أُلغي تفعيل إضافة محظورة فور تفعيلها: %s', $plugin ),
			'critical'
		);

		$this->sweep();
	}

	/**
	 * Remove blocked plugins from wp.org search results.
	 *
	 * @param object|WP_Error $result API result.
	 * @param string          $action API action.
	 * @param object          $args   API arguments.
	 * @return object|WP_Error
	 */
	public function filter_api_results( $result, $action, $args ) {
		if ( is_wp_error( $result ) || empty( $result->plugins ) || ! is_array( $result->plugins ) ) {
			return $result;
		}

		$blocked = self::blocked_slugs();

		foreach ( $result->plugins as $index => $plugin ) {
			$slug = is_array( $plugin ) ? ( $plugin['slug'] ?? '' ) : ( $plugin->slug ?? '' );
			if ( $slug && in_array( strtolower( $slug ), $blocked, true ) ) {
				unset( $result->plugins[ $index ] );
			}
		}

		$result->plugins = array_values( $result->plugins );
		return $result;
	}

	/* ---------------------------------------------------------------------
	 * Filesystem sweep
	 * ------------------------------------------------------------------ */

	/**
	 * Run the sweep at most once every couple of minutes per admin session.
	 *
	 * @return void
	 */
	public function maybe_sweep() {
		if ( get_transient( 'dys_sec_guard_swept' ) ) {
			return;
		}
		set_transient( 'dys_sec_guard_swept', 1, 2 * MINUTE_IN_SECONDS );
		$this->sweep();
	}

	/**
	 * Delete (or quarantine) any blocked plugin present on disk.
	 *
	 * @return array List of paths acted on.
	 */
	public function sweep() {
		$acted   = array();
		$blocked = self::blocked_slugs();
		$autodel = (bool) Ejabh_Settings::get( 'guard_autodelete' );

		if ( ! is_dir( WP_PLUGIN_DIR ) ) {
			return $acted;
		}

		foreach ( $blocked as $slug ) {
			$dir = WP_PLUGIN_DIR . '/' . $slug;
			if ( ! is_dir( $dir ) ) {
				continue;
			}

			if ( $autodel ) {
				// Preserve the evidence before removing it: knowing *which*
				// file-manager build appeared is what identifies the entry point.
				if ( Ejabh_Settings::get( 'quarantine_enabled' ) ) {
					self::quarantine_entry_point( $dir, $slug );
				}

				if ( self::delete_tree( $dir ) ) {
					$acted[] = $slug;
					Ejabh_Logger::log(
						'guard_deleted',
						sprintf( 'حُذف مجلد إضافة محظورة من السيرفر: wp-content/plugins/%s', $slug ),
						'critical'
					);
				} else {
					Ejabh_Logger::log(
						'guard_delete_failed',
						sprintf( 'تعذّر حذف مجلد الإضافة المحظورة wp-content/plugins/%s — تحقّق من صلاحيات الملفات.', $slug ),
						'critical'
					);
				}
			} else {
				Ejabh_Logger::log(
					'guard_detected',
					sprintf( 'رُصدت إضافة محظورة على السيرفر (الحذف التلقائي معطّل): wp-content/plugins/%s', $slug ),
					'critical'
				);
				$acted[] = $slug;
			}
		}

		// Clean any lingering active_plugins entry.
		$active = get_option( 'active_plugins' );
		if ( is_array( $active ) ) {
			$filtered = array_values(
				array_filter(
					$active,
					static function ( $plugin ) {
						return ! self::is_blocked( $plugin );
					}
				)
			);
			if ( count( $filtered ) !== count( $active ) ) {
				update_option( 'active_plugins', $filtered );
			}
		}

		return $acted;
	}

	/**
	 * Keep a copy of a blocked plugin's main file before the directory goes.
	 *
	 * Deleting silently destroys the only evidence of how the site was reached.
	 * One representative PHP file is enough to identify the build later.
	 *
	 * @param string $dir  Plugin directory.
	 * @param string $slug Plugin slug.
	 * @return void
	 */
	private static function quarantine_entry_point( $dir, $slug ) {
		$candidates = array();

		foreach ( (array) @scandir( $dir ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}
			$path = $dir . '/' . $entry;
			if ( is_file( $path ) && 'php' === strtolower( pathinfo( $entry, PATHINFO_EXTENSION ) ) ) {
				$candidates[] = $path;
			}
		}

		if ( ! $candidates ) {
			return;
		}

		// Largest top-level PHP file is almost always the plugin's main file.
		usort(
			$candidates,
			static function ( $a, $b ) {
				return (int) @filesize( $b ) <=> (int) @filesize( $a ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			}
		);

		Ejabh_Quarantine::capture(
			$candidates[0],
			sprintf(
				/* translators: %s: plugin slug. */
				__( 'نسخة محفوظة من إضافة مدير ملفات محظورة (%s) قبل حذفها — للتحقيق.', 'ejabh-security' ),
				$slug
			)
		);
	}

	/**
	 * Recursively delete a directory, refusing anything outside the plugins dir.
	 *
	 * @param string $dir Directory to remove.
	 * @return bool
	 */
	public static function delete_tree( $dir ) {
		$real       = realpath( $dir );
		$plugin_dir = realpath( WP_PLUGIN_DIR );
		$self       = realpath( EJABH_SEC_DIR );

		if ( ! $real || ! $plugin_dir ) {
			return false;
		}

		// Must live strictly inside the plugins directory.
		if ( 0 !== strpos( wp_normalize_path( $real ), trailingslashit( wp_normalize_path( $plugin_dir ) ) ) ) {
			return false;
		}

		// Never delete ourselves.
		if ( $self && ( $real === $self || 0 === strpos( wp_normalize_path( $real ), trailingslashit( wp_normalize_path( $self ) ) ) ) ) {
			return false;
		}

		// Must be at least one level deep (never the plugins dir itself).
		if ( wp_normalize_path( $real ) === wp_normalize_path( $plugin_dir ) ) {
			return false;
		}

		try {
			$items = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $real, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
		} catch ( Exception $e ) {
			return false;
		}

		foreach ( $items as $item ) {
			if ( $item->isLink() ) {
				@unlink( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink
			} elseif ( $item->isDir() ) {
				@rmdir( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rmdir_rmdir
			} else {
				@unlink( $item->getPathname() ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.unlink_unlink
			}
		}

		return @rmdir( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.rmdir_rmdir
	}

	/**
	 * Schedule the periodic sweep.
	 *
	 * @return void
	 */
	public static function schedule() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + 300, 'hourly', self::CRON_HOOK );
		}
	}

	/**
	 * Remove the scheduled sweep.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}
}
