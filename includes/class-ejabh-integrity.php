<?php
/**
 * Plugin and theme integrity audit.
 *
 * WordPress.org publishes a per-file MD5 manifest for every released version of
 * every hosted plugin at
 * `downloads.wordpress.org/plugin-checksums/{slug}/{version}.json`.
 *
 * Comparing the installed files against that manifest is the only reliable way
 * to prove a plugin has not been tampered with. It catches two things nothing
 * else does:
 *
 *  - a legitimate plugin with a backdoor appended to one of its files;
 *  - an *extra* file dropped inside a plugin directory, which is where an
 *    attacker hides a shell so it blends in with thousands of real files.
 *
 * Premium and custom code (this site's Oxpins theme, WP Rocket, the paid Give
 * add-ons) has no published manifest. Those are reported as unverifiable rather
 * than silently passed, because "we could not check" is a materially different
 * answer from "it is clean".
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Verifies installed plugins against wordpress.org checksums.
 */
class Ejabh_Integrity {

	const STATE_OPTION = 'dys_sec_integrity_state';

	/** Files inside a plugin that are expected to change at runtime. */
	const RUNTIME_NOISE = array(
		'.htaccess',
		'index.php',
		'debug.log',
		'error_log',
	);

	/**
	 * Fresh state.
	 *
	 * @return array
	 */
	public static function blank_state() {
		return array(
			'scan_id'      => '',
			'status'       => 'idle',
			'queue'        => array(),
			'checked'      => 0,
			'verified'     => 0,
			'modified'     => 0,
			'unverifiable' => 0,
			'started'      => 0,
			'finished'     => 0,
		);
	}

	/**
	 * Read state.
	 *
	 * @return array
	 */
	public static function state() {
		$state = get_option( self::STATE_OPTION, array() );
		return is_array( $state ) && $state ? array_merge( self::blank_state(), $state ) : self::blank_state();
	}

	/**
	 * Persist state.
	 *
	 * @param array $state State.
	 * @return void
	 */
	private static function save_state( array $state ) {
		update_option( self::STATE_OPTION, $state, false );
	}

	/**
	 * Queue every installed plugin plus the active theme.
	 *
	 * @return array
	 */
	public static function start() {
		Ejabh_Findings::clear_type( 'integrity' );

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$queue = array();
		foreach ( get_plugins() as $file => $data ) {
			$slug = strtok( $file, '/' );
			if ( false !== strpos( $file, '/' ) ) {
				$queue[] = array(
					'type'    => 'plugin',
					'slug'    => $slug,
					'file'    => $file,
					'name'    => $data['Name'],
					'version' => $data['Version'],
				);
			}
		}

		// Themes have no checksum API; they are reported as unverifiable.
		foreach ( wp_get_themes() as $stylesheet => $theme ) {
			$queue[] = array(
				'type'    => 'theme',
				'slug'    => $stylesheet,
				'file'    => '',
				'name'    => $theme->get( 'Name' ),
				'version' => $theme->get( 'Version' ),
			);
		}

		$state             = self::blank_state();
		$state['scan_id']  = substr( md5( uniqid( 'dysint', true ) ), 0, 16 );
		$state['status']   = 'scanning';
		$state['started']  = time();
		$state['queue']    = $queue;

		self::save_state( $state );
		Ejabh_Logger::log( 'integrity_scan_started', sprintf( 'بدأ تدقيق نزاهة %d إضافة/قالب.', count( $queue ) ), 'info' );

		return $state;
	}

	/**
	 * Verify one batch of the queue.
	 *
	 * @return array
	 */
	public static function step() {
		$state = self::state();
		if ( 'scanning' !== $state['status'] ) {
			return $state;
		}

		$budget   = max( 5, (int) Ejabh_Settings::get( 'scan_time_budget' ) );
		$deadline = microtime( true ) + $budget;

		while ( $state['queue'] && microtime( true ) < $deadline ) {
			$item = array_shift( $state['queue'] );
			self::verify_item( $item, $state );
			++$state['checked'];
		}

		if ( ! $state['queue'] ) {
			$state['status']   = 'done';
			$state['finished'] = time();

			Ejabh_Logger::log(
				'integrity_scan_finished',
				sprintf(
					'انتهى تدقيق النزاهة: %d مُتحقَّق، %d مُعدَّل، %d غير قابل للتحقق.',
					$state['verified'],
					$state['modified'],
					$state['unverifiable']
				),
				$state['modified'] > 0 ? 'critical' : 'info'
			);
		}

		self::save_state( $state );
		return $state;
	}

	/**
	 * Abort.
	 *
	 * @return void
	 */
	public static function cancel() {
		$state           = self::state();
		$state['status'] = 'idle';
		$state['queue']  = array();
		self::save_state( $state );
	}

	/**
	 * Verify one plugin or theme.
	 *
	 * @param array $item  Queue entry.
	 * @param array $state Scan state, updated by reference.
	 * @return void
	 */
	private static function verify_item( array $item, array &$state ) {
		$scan_id = $state['scan_id'];
		$label   = sprintf( '%s %s', $item['name'], $item['version'] );

		if ( 'theme' === $item['type'] ) {
			++$state['unverifiable'];
			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'integrity',
					'severity'  => 'medium',
					'rule'      => 'theme_unverifiable',
					'title'     => __( 'قالب لا يمكن التحقق من سلامته', 'ejabh-security' ),
					'target'    => sprintf( 'wp-content/themes/%s — %s', $item['slug'], $label ),
					'snippet'   => __( 'ووردبريس لا ينشر بصمات للقوالب، فلا توجد طريقة آلية لإثبات أن ملفات هذا القالب أصلية. القوالب المدفوعة أو المقرصنة هي الوسيلة الأولى لدخول الأبواب الخلفية — راجع ملفاته يدوياً وتأكد أن مصدره رسمي.', 'ejabh-security' ),
				)
			);
			return;
		}

		// A plugin can legitimately match either of two references: the release
		// published on wordpress.org, or — for plugins WordPress bundles, like
		// Akismet — the build shipped inside core, which differs from the
		// wordpress.org release of the same version number. Accepting a match
		// against either avoids reporting an untouched plugin as tampered with.
		$manifests = array();

		$core = self::core_manifest_for_plugin( $item['slug'] );
		if ( $core ) {
			$manifests['core'] = $core;
		}

		$wporg = self::fetch_manifest( $item['slug'], $item['version'] );
		if ( ! is_wp_error( $wporg ) ) {
			$manifests['wporg'] = $wporg;
		}

		if ( ! $manifests ) {
			++$state['unverifiable'];

			$reason = 'dys_not_hosted' === $wporg->get_error_code()
				? __( 'هذه الإضافة غير منشورة على wordpress.org (مدفوعة أو مخصصة أو مقرصنة)، فلا توجد بصمات رسمية لمقارنتها. إن كانت نسخة مقرصنة فهي خطر مباشر — النسخ المقرصنة تُوزَّع عادةً وبها أبواب خلفية.', 'ejabh-security' )
				: $wporg->get_error_message();

			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'integrity',
					'severity'  => 'medium',
					'rule'      => 'plugin_unverifiable',
					'title'     => __( 'إضافة لا يمكن التحقق من سلامتها', 'ejabh-security' ),
					'target'    => sprintf( 'wp-content/plugins/%s — %s', $item['slug'], $label ),
					'snippet'   => $reason,
				)
			);
			return;
		}

		$dir = trailingslashit( WP_PLUGIN_DIR ) . $item['slug'];
		if ( ! is_dir( $dir ) ) {
			return;
		}

		// The union of every path either reference knows about.
		$known = array();
		foreach ( $manifests as $manifest ) {
			$known += array_fill_keys( array_keys( $manifest ), true );
		}

		$modified = array();
		$missing  = array();

		foreach ( array_keys( $known ) as $rel ) {
			if ( in_array( $rel, self::RUNTIME_NOISE, true ) ) {
				continue;
			}

			$abs = $dir . '/' . $rel;

			if ( ! file_exists( $abs ) ) {
				// Only a real absence if every reference expects the file.
				$expected_by_all = true;
				foreach ( $manifests as $manifest ) {
					if ( ! isset( $manifest[ $rel ] ) ) {
						$expected_by_all = false;
						break;
					}
				}
				if ( $expected_by_all ) {
					$missing[] = $rel;
				}
				continue;
			}
			if ( ! is_readable( $abs ) ) {
				continue;
			}

			$contents = file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			if ( false === $contents ) {
				continue;
			}

			if ( ! self::matches_any( $contents, $rel, $manifests ) ) {
				$modified[] = $rel;
			}
		}

		$extra = self::find_extra_files( $dir, $known );

		if ( $modified ) {
			++$state['modified'];
			foreach ( array_slice( $modified, 0, 25 ) as $rel ) {
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'integrity',
						'severity'  => 'critical',
						'rule'      => 'plugin_file_modified',
						'title'     => __( 'ملف إضافة مُعدَّل — لا يطابق النسخة الرسمية', 'ejabh-security' ),
						'target'    => sprintf( 'wp-content/plugins/%s/%s', $item['slug'], $rel ),
						'snippet'   => sprintf(
							/* translators: 1: plugin label, 2: reference source. */
							__( 'محتوى هذا الملف يختلف عن %2$s الخاصة بـ %1$s. إما أن أحداً عدّله يدوياً، أو أن الإضافة مُصابة. أعد تثبيت الإضافة من مصدرها الرسمي بعد فحص الملف.', 'ejabh-security' ),
							$label,
							'core' === $source ? __( 'النسخة المرفقة مع نواة ووردبريس', 'ejabh-security' ) : __( 'النسخة المنشورة على wordpress.org', 'ejabh-security' )
						),
					)
				);
			}
		}

		if ( $extra ) {
			foreach ( array_slice( $extra, 0, 25 ) as $rel ) {
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'integrity',
						'severity'  => 'critical',
						'rule'      => 'plugin_extra_file',
						'title'     => __( 'ملف PHP دخيل داخل مجلد إضافة رسمية', 'ejabh-security' ),
						'target'    => sprintf( 'wp-content/plugins/%s/%s', $item['slug'], $rel ),
						'snippet'   => __( 'هذا الملف غير موجود في النسخة الرسمية للإضافة. إضافة ملف PHP إلى مجلد إضافة سليمة هو أسلوب كلاسيكي لإخفاء باب خلفي وسط آلاف الملفات الحقيقية.', 'ejabh-security' ),
					)
				);
			}
		}

		if ( $missing && ! $modified ) {
			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'integrity',
					'severity'  => 'low',
					'rule'      => 'plugin_file_missing',
					'title'     => __( 'ملفات ناقصة من إضافة', 'ejabh-security' ),
					'target'    => sprintf( 'wp-content/plugins/%s — %s', $item['slug'], $label ),
					'snippet'   => sprintf(
						/* translators: 1: count, 2: sample file list. */
						__( '%1$d ملف موجود في النسخة الرسمية وغير موجود هنا. غالباً حذفها سكانر الاستضافة أو تنظيف سابق. أمثلة: %2$s', 'ejabh-security' ),
						count( $missing ),
						implode( ', ', array_slice( $missing, 0, 5 ) )
					),
				)
			);
		}

		if ( ! $modified && ! $extra ) {
			++$state['verified'];
		}
	}

	/**
	 * Does this file's content match its entry in at least one reference?
	 *
	 * @param string $contents  File contents.
	 * @param string $rel       Path relative to the plugin directory.
	 * @param array  $manifests Map of source => file map.
	 * @return bool
	 */
	private static function matches_any( $contents, $rel, array $manifests ) {
		$md5        = md5( $contents );
		$sha256     = null;
		$normalised = null;

		foreach ( $manifests as $manifest ) {
			if ( ! isset( $manifest[ $rel ] ) ) {
				continue;
			}

			$hashes = $manifest[ $rel ];

			if ( ! empty( $hashes['md5'] ) && hash_equals( (string) $hashes['md5'], $md5 ) ) {
				return true;
			}

			if ( ! empty( $hashes['sha256'] ) ) {
				if ( null === $sha256 ) {
					$sha256 = hash( 'sha256', $contents );
				}
				if ( hash_equals( (string) $hashes['sha256'], $sha256 ) ) {
					return true;
				}
			}

			// Line-ending-only differences are an editing artefact, not an attack.
			if ( ! empty( $hashes['md5'] ) ) {
				if ( null === $normalised ) {
					$normalised = md5( str_replace( "\r\n", "\n", $contents ) );
				}
				if ( hash_equals( (string) $hashes['md5'], $normalised ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Files present on disk that no reference manifest lists.
	 *
	 * @param string $dir      Plugin directory.
	 * @param array  $manifest Map of known relative path => true.
	 * @return array Relative paths.
	 */
	private static function find_extra_files( $dir, array $manifest ) {
		$extra = array();

		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
		} catch ( Exception $e ) {
			return $extra;
		}

		$base = trailingslashit( wp_normalize_path( $dir ) );

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}

			// Only executable code matters here; stray images and caches do not.
			$ext = strtolower( $file->getExtension() );
			if ( ! in_array( $ext, array( 'php', 'phtml', 'php5', 'php7', 'phar', 'pht', 'inc' ), true ) ) {
				continue;
			}

			$rel = str_replace( $base, '', wp_normalize_path( $file->getPathname() ) );

			if ( isset( $manifest[ $rel ] ) || in_array( $rel, self::RUNTIME_NOISE, true ) ) {
				continue;
			}

			$extra[] = $rel;
		}

		return $extra;
	}

	/**
	 * Build a manifest for a core-bundled plugin from WordPress's own checksums.
	 *
	 * @param string $slug Plugin slug.
	 * @return array Empty when the plugin is not bundled with core.
	 */
	private static function core_manifest_for_plugin( $slug ) {
		$checksums = Ejabh_Core_Integrity::checksums();
		if ( is_wp_error( $checksums ) ) {
			return array();
		}

		$prefix = 'wp-content/plugins/' . $slug . '/';
		$out    = array();

		foreach ( $checksums as $path => $md5 ) {
			if ( 0 !== strpos( $path, $prefix ) ) {
				continue;
			}
			$out[ substr( $path, strlen( $prefix ) ) ] = array( 'md5' => $md5 );
		}

		return $out;
	}

	/**
	 * Fetch and cache the official file manifest for a plugin version.
	 *
	 * @param string $slug    Plugin slug.
	 * @param string $version Installed version.
	 * @return array|WP_Error Map of relative path => hash array.
	 */
	public static function fetch_manifest( $slug, $version ) {
		$slug    = sanitize_key( $slug );
		$version = trim( (string) $version );

		if ( ! $slug || ! $version ) {
			return new WP_Error( 'dys_bad_args', __( 'لا يمكن تحديد اسم الإضافة أو إصدارها.', 'ejabh-security' ) );
		}

		$cache_key = 'dys_sec_cksum_' . md5( $slug . '|' . $version );
		$cached    = get_transient( $cache_key );

		if ( is_array( $cached ) ) {
			return $cached;
		}
		if ( 'not-hosted' === $cached ) {
			return new WP_Error( 'dys_not_hosted', __( 'غير منشورة على wordpress.org.', 'ejabh-security' ) );
		}

		$url = sprintf(
			'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
			rawurlencode( $slug ),
			rawurlencode( $version )
		);

		$response = wp_remote_get( $url, array( 'timeout' => 25 ) );

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'dys_http', $response->get_error_message() );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );

		if ( 404 === $code ) {
			// Either a premium plugin or a version that was never published.
			set_transient( $cache_key, 'not-hosted', WEEK_IN_SECONDS );
			return new WP_Error( 'dys_not_hosted', __( 'غير منشورة على wordpress.org.', 'ejabh-security' ) );
		}

		if ( 200 !== $code ) {
			return new WP_Error(
				'dys_http',
				sprintf(
					/* translators: %d: HTTP status code. */
					__( 'استجابة غير متوقعة من wordpress.org (%d).', 'ejabh-security' ),
					$code
				)
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body['files'] ) || ! is_array( $body['files'] ) ) {
			return new WP_Error( 'dys_bad_manifest', __( 'ملف البصمات الرسمي غير صالح.', 'ejabh-security' ) );
		}

		set_transient( $cache_key, $body['files'], WEEK_IN_SECONDS );
		return $body['files'];
	}
}
