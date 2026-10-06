<?php
/**
 * WordPress core integrity verification.
 *
 * Compares every core file against the official MD5 checksums published by
 * WordPress.org. This is the single most reliable malware check available for
 * a WordPress install: it finds injected code in core files and, just as
 * importantly, finds *extra* PHP files dropped into wp-admin/ and wp-includes/,
 * which is where attackers most often hide a second-stage backdoor.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Core checksum verification.
 */
class Ejabh_Core_Integrity {

	const CACHE_KEY = 'dys_sec_core_checksums';

	/**
	 * Fetch the official checksum map for the running version.
	 *
	 * @param bool $force Skip the cache.
	 * @return array|WP_Error Map of relative path => md5.
	 */
	public static function checksums( $force = false ) {
		global $wp_version;

		if ( ! $force ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( is_array( $cached ) && $cached ) {
				return $cached;
			}
		}

		$locales = array_unique( array( get_locale(), 'en_US' ) );

		foreach ( $locales as $locale ) {
			$url = add_query_arg(
				array(
					'version' => $wp_version,
					'locale'  => $locale,
				),
				'https://api.wordpress.org/core/checksums/1.0/'
			);

			$response = wp_remote_get( $url, array( 'timeout' => 30 ) );
			if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
				continue;
			}

			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			if ( ! empty( $body['checksums'] ) && is_array( $body['checksums'] ) ) {
				set_transient( self::CACHE_KEY, $body['checksums'], 12 * HOUR_IN_SECONDS );
				return $body['checksums'];
			}
		}

		return new WP_Error(
			'dys_checksums_unavailable',
			__( 'تعذّر جلب بصمات ملفات ووردبريس الرسمية من api.wordpress.org. تحقّق من اتصال السيرفر بالإنترنت.', 'ejabh-security' )
		);
	}

	/**
	 * Run the full integrity check and record findings.
	 *
	 * @param string $scan_id Scan identifier for grouping findings.
	 * @return array Stats: checked, modified, missing, unknown.
	 */
	public static function run( $scan_id ) {
		$stats = array(
			'checked'  => 0,
			'modified' => 0,
			'missing'  => 0,
			'unknown'  => 0,
			'error'    => '',
		);

		$checksums = self::checksums();
		if ( is_wp_error( $checksums ) ) {
			$stats['error'] = $checksums->get_error_message();
			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => 'medium',
					'rule'      => 'core_checksums_unavailable',
					'title'     => __( 'تعذّر التحقق من سلامة ملفات النواة', 'ejabh-security' ),
					'target'    => 'wp-includes/version.php',
					'snippet'   => $stats['error'],
				)
			);
			return $stats;
		}

		$root = self::root();

		foreach ( $checksums as $rel => $md5 ) {
			// Bundled plugins and themes are legitimately updated or deleted by
			// site owners, so they are handled separately below.
			if ( 0 === strpos( $rel, 'wp-content/' ) ) {
				continue;
			}

			++$stats['checked'];
			$abs = $root . $rel;

			if ( ! file_exists( $abs ) ) {
				++$stats['missing'];
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'file',
						'severity'  => 'high',
						'rule'      => 'core_file_missing',
						'title'     => __( 'ملف أساسي من ووردبريس مفقود', 'ejabh-security' ),
						'target'    => $rel,
						'snippet'   => __( 'الملف موجود في النسخة الرسمية لكنه غير موجود على السيرفر. قد يكون حُذف بواسطة مخترق أو سكانر الاستضافة.', 'ejabh-security' ),
					)
				);
				continue;
			}

			if ( ! is_readable( $abs ) ) {
				continue;
			}

			$contents = file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			if ( false === $contents ) {
				continue;
			}

			if ( hash_equals( $md5, md5( $contents ) ) ) {
				continue;
			}

			// A CRLF-only difference is an editing artefact, not an attack.
			$normalised = str_replace( "\r\n", "\n", $contents );
			if ( hash_equals( $md5, md5( $normalised ) ) ) {
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'file',
						'severity'  => 'low',
						'rule'      => 'core_file_line_endings',
						'title'     => __( 'ملف نواة يختلف في نهايات الأسطر فقط (غير خطير)', 'ejabh-security' ),
						'target'    => $rel,
						'snippet'   => __( 'المحتوى مطابق للنسخة الرسمية بعد تطبيع نهايات الأسطر (CRLF ← LF). سببه تحرير الملف على Windows.', 'ejabh-security' ),
					)
				);
				continue;
			}

			++$stats['modified'];
			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => 'critical',
					'rule'      => 'core_file_modified',
					'title'     => __( 'ملف من نواة ووردبريس مُعدَّل — لا يطابق النسخة الرسمية', 'ejabh-security' ),
					'target'    => $rel,
					'snippet'   => sprintf(
						/* translators: 1: expected md5, 2: actual md5. */
						__( 'البصمة المتوقعة: %1$s — البصمة الفعلية: %2$s. استبدل الملف من نسخة ووردبريس الرسمية وافحص محتواه أولاً.', 'ejabh-security' ),
						$md5,
						md5( $contents )
					),
				)
			);
		}

		$stats['unknown'] = self::find_unknown_core_files( $scan_id, $checksums );

		return $stats;
	}

	/**
	 * Find PHP files inside wp-admin/ and wp-includes/ that WordPress does not ship.
	 *
	 * @param string $scan_id   Scan identifier.
	 * @param array  $checksums Official checksum map.
	 * @return int Number of unknown files found.
	 */
	private static function find_unknown_core_files( $scan_id, array $checksums ) {
		$root  = self::root();
		$found = 0;

		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			$base = $root . $dir;
			if ( ! is_dir( $base ) ) {
				continue;
			}

			try {
				$iterator = new RecursiveIteratorIterator(
					new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
					RecursiveIteratorIterator::LEAVES_ONLY
				);
			} catch ( Exception $e ) {
				continue;
			}

			foreach ( $iterator as $file ) {
				if ( ! $file->isFile() ) {
					continue;
				}
				if ( 'php' !== strtolower( $file->getExtension() ) ) {
					continue;
				}

				$rel = self::relative( $file->getPathname() );
				if ( '' === $rel || isset( $checksums[ $rel ] ) ) {
					continue;
				}

				++$found;
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'file',
						'severity'  => 'critical',
						'rule'      => 'core_unknown_file',
						'title'     => __( 'ملف PHP غريب داخل مجلد نواة ووردبريس — مرشّح قوي لباب خلفي', 'ejabh-security' ),
						'target'    => $rel,
						'snippet'   => sprintf(
							/* translators: %s: file size. */
							__( 'هذا الملف غير موجود في نسخة ووردبريس الرسمية. ووردبريس لا يضيف ملفات إلى wp-admin أو wp-includes، والإضافات كذلك لا تفعل. الحجم: %s بايت.', 'ejabh-security' ),
							number_format_i18n( $file->getSize() )
						),
					)
				);
			}
		}

		return $found;
	}

	/**
	 * Absolute path to the WordPress root with a trailing slash.
	 *
	 * @return string
	 */
	public static function root() {
		return trailingslashit( wp_normalize_path( ABSPATH ) );
	}

	/**
	 * Convert an absolute path to a site-relative one.
	 *
	 * @param string $path Absolute path.
	 * @return string Relative path, or '' when outside the site root.
	 */
	public static function relative( $path ) {
		$path = wp_normalize_path( $path );
		$root = self::root();

		if ( 0 !== strpos( $path, $root ) ) {
			return '';
		}
		return substr( $path, strlen( $root ) );
	}
}
