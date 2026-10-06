<?php
/**
 * Hardening checks and one-click fixes.
 *
 * Detection without remediation just produces a to-do list nobody actions, so
 * every check here that *can* be fixed safely ships with the fix.
 *
 * Editing wp-config.php is the risky part, and it is treated accordingly: the
 * file is backed up outside the web root first, the replacement is parsed with
 * token_get_all(TOKEN_PARSE) before it is written, the required constants are
 * re-verified afterwards, and any failure rolls back to the backup.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Site hardening audit and remediation.
 */
class Ejabh_Hardening {

	/** Marker used for our managed .htaccess blocks. */
	const MARKER = 'Ejabh Security';

	/** The eight authentication constants. */
	const SALT_KEYS = array(
		'AUTH_KEY',
		'SECURE_AUTH_KEY',
		'LOGGED_IN_KEY',
		'NONCE_KEY',
		'AUTH_SALT',
		'SECURE_AUTH_SALT',
		'LOGGED_IN_SALT',
		'NONCE_SALT',
	);

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'admin_post_dys_sec_harden', array( $this, 'handle_fix' ) );

		if ( Ejabh_Settings::get( 'abilities_require_login' ) ) {
			add_filter( 'rest_pre_dispatch', array( __CLASS__, 'gate_abilities' ), 10, 3 );
		}
	}

	/**
	 * Refuse anonymous calls to the Abilities API (WordPress 6.9+).
	 *
	 * Core already requires the `read` capability to *list* abilities, but
	 * running one is gated only by that ability's own permission callback —
	 * and any plugin can register an ability whose callback says yes to
	 * everyone. Requiring a signed-in user (who has passed 2FA) closes that
	 * whole class of mistake for every plugin at once.
	 *
	 * @param mixed           $result  Short-circuit value.
	 * @param WP_REST_Server  $server  Server.
	 * @param WP_REST_Request $request Request.
	 * @return mixed
	 */
	public static function gate_abilities( $result, $server, $request ) {
		if ( null !== $result || ! $request instanceof WP_REST_Request ) {
			return $result;
		}
		if ( 0 !== strpos( (string) $request->get_route(), '/wp-abilities/' ) || is_user_logged_in() ) {
			return $result;
		}
		return new WP_Error(
			'ejabh_abilities_login_required',
			__( 'Sign in to use this endpoint.', 'ejabh-security' ),
			array( 'status' => 401 )
		);
	}

	/* ---------------------------------------------------------------------
	 * Locating wp-config.php
	 * ------------------------------------------------------------------ */

	/**
	 * Path to the live wp-config.php.
	 *
	 * WordPress also supports the file one directory above the install, as long
	 * as that directory does not contain another wp-settings.php.
	 *
	 * @return string Empty string when not found.
	 */
	public static function config_path() {
		$here = ABSPATH . 'wp-config.php';
		if ( file_exists( $here ) ) {
			return $here;
		}

		$above = dirname( ABSPATH ) . '/wp-config.php';
		if ( file_exists( $above ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			return $above;
		}

		return '';
	}

	/**
	 * Directory holding wp-config backups, created and protected on demand.
	 *
	 * @return string
	 */
	public static function backup_dir() {
		$dir = WP_CONTENT_DIR . '/dys-security-backups';

		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// These backups contain live database credentials: they must never be
		// reachable over HTTP.
		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
				$htaccess,
				"<IfModule authz_core_module>\n\tRequire all denied\n</IfModule>\n<IfModule !authz_core_module>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n"
			);
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		}

		return $dir;
	}

	/* ---------------------------------------------------------------------
	 * Checks
	 * ------------------------------------------------------------------ */

	/**
	 * Run every hardening check.
	 *
	 * @return array List of check descriptors.
	 */
	public static function checks() {
		$checks = array();
		$config = self::config_path();

		// --- Authentication salts ---
		$defaults = self::default_salts();
		$checks[] = array(
			'id'     => 'salts',
			'label'  => __( 'مفاتيح الأمان (Salts) في wp-config.php', 'ejabh-security' ),
			'status' => $defaults ? 'fail' : 'ok',
			'detail' => $defaults
				? sprintf(
					/* translators: %s: comma-separated constant names. */
					__( '%s ما زالت بالقيمة الافتراضية. هذه المفاتيح تُوقّع كوكيز الدخول — كونها معروفة يعني أن الجلسات قابلة للتزوير عند أي تسريب لقاعدة البيانات.', 'ejabh-security' ),
					implode( '، ', $defaults )
				)
				: __( 'المفاتيح الثمانية مُولَّدة بقيم فريدة.', 'ejabh-security' ),
			'fix'    => $defaults ? 'regenerate_salts' : '',
			'button' => __( 'ولّد مفاتيح جديدة الآن', 'ejabh-security' ),
			'warn'   => __( 'سيؤدي هذا إلى إخراج كل المستخدمين من الموقع (بمن فيهم أنت) وإبطال أي كوكي مزوّر. متابعة؟', 'ejabh-security' ),
		);

		// --- Dashboard file editor ---
		$editor_off = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$checks[]   = array(
			'id'     => 'file_edit',
			'label'  => __( 'محرر ملفات القوالب والإضافات', 'ejabh-security' ),
			'status' => $editor_off ? 'ok' : 'fail',
			'detail' => $editor_off
				? __( 'مُعطَّل عبر DISALLOW_FILE_EDIT.', 'ejabh-security' )
				: __( 'مفتوح. أي حساب مدير مخترق يستطيع كتابة باب خلفي مباشرة من لوحة التحكم دون رفع أي ملف.', 'ejabh-security' ),
			'fix'    => $editor_off ? '' : 'disallow_file_edit',
			'button' => __( 'تعطيل محرر الملفات', 'ejabh-security' ),
			'warn'   => '',
		);

		// --- Plugin/theme installation from the dashboard ---
		$mods_off = defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS;
		$checks[] = array(
			'id'     => 'file_mods',
			'label'  => __( 'تثبيت وتحديث الإضافات من لوحة التحكم', 'ejabh-security' ),
			'status' => $mods_off ? 'ok' : 'warn',
			'detail' => $mods_off
				? __( 'مُعطَّل تماماً عبر DISALLOW_FILE_MODS. لن تعمل التحديثات التلقائية أيضاً.', 'ejabh-security' )
				: __( 'مفتوح. هذا هو الوضع الطبيعي، والتقييد على المالك الواحد يغطيه أصلاً. فعّل هذا فقط إذا أردت تجميد الموقع بالكامل — وسيمنع التحديثات الأمنية أيضاً.', 'ejabh-security' ),
			'fix'    => $mods_off ? 'allow_file_mods' : 'disallow_file_mods',
			'button' => $mods_off ? __( 'إعادة السماح بالتحديثات', 'ejabh-security' ) : __( 'تجميد كل التعديلات', 'ejabh-security' ),
			'warn'   => $mods_off ? '' : __( 'سيمنع هذا تحديثات ووردبريس والإضافات نهائياً حتى تُلغيه. متابعة؟', 'ejabh-security' ),
		);

		// --- Exposed files in the web root ---
		$exposed  = self::exposed_files();
		$checks[] = array(
			'id'     => 'exposed',
			'label'  => __( 'ملفات حسّاسة مكشوفة في مجلد الموقع', 'ejabh-security' ),
			'status' => $exposed ? 'fail' : 'ok',
			'detail' => $exposed
				? sprintf(
					/* translators: 1: count, 2: file list. */
					__( '%1$d ملف قابل للتنزيل من الإنترنت: %2$s. نسخ قواعد البيانات تحتوي كل هاشات كلمات المرور وبيانات المستخدمين والعملاء.', 'ejabh-security' ),
					count( $exposed ),
					implode( '، ', array_slice( wp_list_pluck( $exposed, 'name' ), 0, 6 ) )
				)
				: __( 'لا توجد نسخ قواعد بيانات أو أرشيفات أو سجلات مكشوفة في جذر الموقع.', 'ejabh-security' ),
			'fix'    => $exposed ? 'protect_exposed' : '',
			'button' => __( 'حظر الوصول إليها عبر .htaccess', 'ejabh-security' ),
			'warn'   => '',
			'extra'  => $exposed,
		);

		// --- PHP execution inside uploads ---
		$uploads     = wp_get_upload_dir();
		$uploads_dir = isset( $uploads['basedir'] ) ? $uploads['basedir'] : '';
		$uploads_ok  = $uploads_dir && self::has_marker( $uploads_dir . '/.htaccess' );
		$checks[]    = array(
			'id'     => 'uploads_php',
			'label'  => __( 'تنفيذ PHP داخل مجلد الوسائط (uploads)', 'ejabh-security' ),
			'status' => $uploads_ok ? 'ok' : 'fail',
			'detail' => $uploads_ok
				? __( 'محظور عبر .htaccess. أي ملف PHP يُرفَع إلى هناك لن يعمل.', 'ejabh-security' )
				: __( 'غير محظور. إن نجح المخترق في رفع ملف PHP إلى uploads فسيُنفَّذ — وهذا أشيع مسار للأبواب الخلفية.', 'ejabh-security' ),
			'fix'    => $uploads_ok ? '' : 'protect_uploads',
			'button' => __( 'منع تنفيذ PHP في uploads', 'ejabh-security' ),
			'warn'   => '',
		);

		// --- Directory listing ---
		$root_ht  = self::has_marker( ABSPATH . '.htaccess' );
		$checks[] = array(
			'id'     => 'root_rules',
			'label'  => __( 'قواعد الحماية في .htaccess الرئيسي', 'ejabh-security' ),
			'status' => $root_ht ? 'ok' : 'warn',
			'detail' => $root_ht
				? __( 'قواعد Ejabh Security مُركّبة: حظر الملفات الحسّاسة وتعطيل فهرسة المجلدات.', 'ejabh-security' )
				: __( 'ملف .htaccess يحتوي قواعد ووردبريس الافتراضية فقط، بلا أي تحصين.', 'ejabh-security' ),
			'fix'    => $root_ht ? '' : 'protect_exposed',
			'button' => __( 'تركيب قواعد الحماية', 'ejabh-security' ),
			'warn'   => '',
		);

		// --- PHP error log in the web root ---
		$log      = ABSPATH . 'error_log';
		$has_log  = file_exists( $log );
		$log_size = $has_log ? (int) filesize( $log ) : 0;
		$checks[] = array(
			'id'     => 'error_log',
			'label'  => __( 'سجل أخطاء PHP داخل مجلد الموقع', 'ejabh-security' ),
			'status' => $has_log ? 'warn' : 'ok',
			'detail' => $has_log
				? sprintf(
					/* translators: %s: human readable file size. */
					__( 'يوجد error_log بحجم %s في جذر الموقع. يكشف المسارات المطلقة للسيرفر وأسماء الإضافات — معلومات يحتاجها المخترق. حظر الوصول إليه يحلّ المشكلة الأمنية؛ ولنقله خارج مجلد الموقع نهائياً اضبط توجيه error_log من MultiPHP INI Editor في cPanel.', 'ejabh-security' ),
					size_format( $log_size )
				)
				: __( 'لا يوجد سجل أخطاء مكشوف في جذر الموقع.', 'ejabh-security' ),
			'fix'    => $has_log ? 'purge_error_log' : '',
			'button' => __( 'حظره وتفريغ محتواه', 'ejabh-security' ),
			'warn'   => __( 'سيُحذف محتوى سجل الأخطاء بالكامل. متابعة؟', 'ejabh-security' ),
		);

		// --- Self-registration ---
		$open     = (bool) get_option( 'users_can_register' );
		$role     = (string) get_option( 'default_role' );
		$checks[] = array(
			'id'     => 'registration',
			'label'  => __( 'التسجيل الذاتي للزوار', 'ejabh-security' ),
			'status' => $open ? ( in_array( $role, array( 'administrator', 'editor' ), true ) ? 'fail' : 'warn' ) : 'ok',
			'detail' => $open
				? sprintf(
					/* translators: %s: default role. */
					__( 'مفتوح، والدور الافتراضي "%s". قد يكون مطلوباً إن كان الموقع يستقبل تسجيل متبرعين أو عملاء (GiveWP، WooCommerce)، فلا تُغلقه إلا إن تأكدت أنه غير مستخدم.', 'ejabh-security' ),
					$role
				)
				: __( 'مغلق.', 'ejabh-security' ),
			'fix'    => '',
			'button' => '',
			'warn'   => '',
		);

		// --- WordPress 7.0: AI provider keys stored in the database ---
		$ai_keys = self::db_stored_ai_keys();
		if ( function_exists( 'wp_get_connectors' ) ) {
			$checks[] = array(
				'id'     => 'ai_keys',
				'label'  => __( 'مفاتيح خدمات الذكاء الاصطناعي (ووردبريس 7)', 'ejabh-security' ),
				'status' => $ai_keys ? 'warn' : 'ok',
				'detail' => $ai_keys
					? sprintf(
						/* translators: %s: provider names. */
						__( 'مفاتيح %s محفوظة نصاً واضحاً في جدول wp_options. أي نسخة قاعدة بيانات مسرّبة أو ثغرة حقن SQL تكشفها، ومن يملكها يستهلك رصيدكم المدفوع. الأأمن نقلها إلى wp-config.php كثوابت — ووردبريس يقرأ الثابت قبل قاعدة البيانات.', 'ejabh-security' ),
						implode( '، ', wp_list_pluck( $ai_keys, 'name' ) )
					)
					: __( 'لا توجد مفاتيح مزوّدي ذكاء اصطناعي محفوظة في قاعدة البيانات.', 'ejabh-security' ),
				'fix'    => $ai_keys ? 'move_ai_keys' : '',
				'button' => __( 'انقلها إلى wp-config.php', 'ejabh-security' ),
				'warn'   => __( 'ستُكتب المفاتيح في wp-config.php ثم تُحذف من قاعدة البيانات. متابعة؟', 'ejabh-security' ),
			);
		}

		// --- WordPress 6.9+: Abilities runnable by anonymous visitors ---
		if ( function_exists( 'wp_get_abilities' ) ) {
			$gate    = (bool) Ejabh_Settings::get( 'abilities_require_login' );
			$exposed = $gate ? array() : self::anonymous_abilities();
			$risky   = array_filter(
				$exposed,
				static function ( $a ) {
					return ! $a['readonly'];
				}
			);
			$checks[] = array(
				'id'     => 'abilities',
				'label'  => __( 'واجهة القدرات (Abilities API) للزوار المجهولين', 'ejabh-security' ),
				'status' => $gate ? 'ok' : ( $risky ? 'fail' : ( $exposed ? 'warn' : 'ok' ) ),
				'detail' => $gate
					? __( 'مقفلة: تنفيذ أي قدرة عبر REST يتطلب تسجيل دخول (ومن ثَمّ رمز التحقق). هذا يحمي من أي إضافة تسجّل قدرة بصلاحيات مفتوحة.', 'ejabh-security' )
					: ( $exposed
						? sprintf(
							/* translators: %s: ability names. */
							__( 'قدرات يستطيع أي زائر تنفيذها دون تسجيل دخول: %s', 'ejabh-security' ),
							implode( '، ', wp_list_pluck( $exposed, 'name' ) )
						)
						: __( 'لا توجد حالياً قدرة مكشوفة للزوار، لكن أي إضافة جديدة قد تضيف واحدة.', 'ejabh-security' ) ),
				'fix'    => $gate ? '' : 'gate_abilities',
				'button' => __( 'اشترط تسجيل الدخول', 'ejabh-security' ),
				'warn'   => '',
			);
		}

		// --- Password hashes older than WordPress 6.8's bcrypt ---
		$legacy_admins = self::legacy_hash_admins();
		$checks[]      = array(
			'id'     => 'password_hashes',
			'label'  => __( 'تشفير كلمات مرور المديرين', 'ejabh-security' ),
			'status' => $legacy_admins ? 'warn' : 'ok',
			'detail' => $legacy_admins
				? sprintf(
					/* translators: %s: user logins. */
					__( 'منذ ووردبريس 6.8 تُشفَّر كلمات المرور بخوارزمية bcrypt الأقوى، ويُحدَّث التشفير تلقائياً عند أول دخول. هذه الحسابات ما زالت بالتشفير القديم، أي أنها لم تسجّل دخولها منذ التحديث: %s. إن لم تكن مستخدمة فأنزِل صلاحياتها أو احذفها.', 'ejabh-security' ),
					implode( '، ', $legacy_admins )
				)
				: __( 'كل حسابات المدير بتشفير bcrypt الحديث.', 'ejabh-security' ),
			'fix'    => '',
			'button' => '',
			'warn'   => '',
		);

		// --- wp-config writability (affects whether fixes can run at all) ---
		$writable = $config && is_writable( $config );
		$checks[] = array(
			'id'     => 'config_writable',
			'label'  => __( 'إمكانية تعديل wp-config.php', 'ejabh-security' ),
			'status' => $writable ? 'warn' : 'ok',
			'detail' => $writable
				? __( 'الملف قابل للكتابة من قِبل السيرفر. هذا مطلوب لتطبيق الإصلاحات التلقائية أعلاه، لكن الأفضل بعد الانتهاء ضبط صلاحياته على 400 أو 440.', 'ejabh-security' )
				: __( 'غير قابل للكتابة — وهذا أأمن. لتطبيق إصلاحات wp-config التلقائية ستحتاج رفع الصلاحية مؤقتاً إلى 644.', 'ejabh-security' ),
			'fix'    => '',
			'button' => '',
			'warn'   => '',
		);

		return $checks;
	}

	/**
	 * AI connector keys that live in wp_options rather than wp-config/env.
	 *
	 * @return array List of {name, option, constant}.
	 */
	public static function db_stored_ai_keys() {
		if ( ! function_exists( 'wp_get_connectors' ) ) {
			return array();
		}

		$out = array();
		foreach ( (array) wp_get_connectors() as $connector ) {
			$auth = isset( $connector['authentication'] ) ? (array) $connector['authentication'] : array();
			if ( 'api_key' !== ( $auth['method'] ?? '' ) || empty( $auth['setting_name'] ) ) {
				continue;
			}

			$constant = (string) ( $auth['constant_name'] ?? '' );
			if ( $constant && defined( $constant ) && '' !== (string) constant( $constant ) ) {
				continue;
			}
			$env = (string) ( $auth['env_var_name'] ?? '' );
			if ( $env && '' !== (string) getenv( $env ) ) {
				continue;
			}

			$value = get_option( $auth['setting_name'], '' );
			if ( is_string( $value ) && '' !== $value ) {
				$out[] = array(
					'name'     => (string) ( $connector['name'] ?? $auth['setting_name'] ),
					'option'   => (string) $auth['setting_name'],
					'constant' => $constant,
				);
			}
		}

		return $out;
	}

	/**
	 * Write DB-stored AI keys into wp-config.php as constants, then delete them
	 * from the database.
	 *
	 * @return array {ok, msg}
	 */
	public static function move_ai_keys() {
		$keys = array_filter(
			self::db_stored_ai_keys(),
			static function ( $k ) {
				return '' !== $k['constant'] && preg_match( '/^[A-Z][A-Z0-9_]*$/', $k['constant'] );
			}
		);

		if ( ! $keys ) {
			return array(
				'ok'  => false,
				'msg' => __( 'لا توجد مفاتيح يمكن نقلها.', 'ejabh-security' ),
			);
		}

		$path = self::config_path();
		if ( ! $path ) {
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر العثور على wp-config.php.', 'ejabh-security' ),
			);
		}

		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$insert  = array();

		foreach ( $keys as $key ) {
			$line    = sprintf( "define( '%s', '%s' );", $key['constant'], self::esc_php_single( (string) get_option( $key['option'], '' ) ) );
			$pattern = '/^[ \t]*define\(\s*([\'"])' . preg_quote( $key['constant'], '/' ) . '\1\s*,\s*(?:([\'"])(?:\\\\.|(?!\2).)*\2|[^)]*)\s*\)\s*;[ \t]*$/m';

			// Literal replacement: an API key may well contain `$`.
			$replaced = self::replace_literal( $pattern, $line, $content, $count );
			if ( null === $replaced ) {
				return array(
					'ok'  => false,
					'msg' => __( 'خطأ أثناء معالجة نص wp-config.php.', 'ejabh-security' ),
				);
			}
			if ( $count ) {
				$content = $replaced;
			} else {
				$insert[ $key['constant'] ] = $line;
			}
		}

		if ( $insert ) {
			$content = self::insert_lines( $content, $insert );
		}

		$result = self::write_config( $content, 'AI connector keys → ' . implode( ', ', wp_list_pluck( $keys, 'constant' ) ) );
		if ( empty( $result['ok'] ) ) {
			return $result;
		}

		// Only now that the constants are safely on disk.
		foreach ( $keys as $key ) {
			delete_option( $key['option'] );
		}

		$result['msg'] = sprintf(
			/* translators: %s: constant names. */
			__( 'نُقلت المفاتيح إلى wp-config.php (%s) وحُذفت من قاعدة البيانات.', 'ejabh-security' ),
			implode( '، ', wp_list_pluck( $keys, 'constant' ) )
		);

		return $result;
	}

	/**
	 * REST-exposed abilities whose permission callback admits a logged-out
	 * visitor.
	 *
	 * Calling a permission callback is exactly what core does for every
	 * anonymous request to the run endpoint, so probing it here is no riskier
	 * than an attacker doing the same.
	 *
	 * @return array List of {name, readonly}.
	 */
	public static function anonymous_abilities() {
		if ( ! function_exists( 'wp_get_abilities' ) ) {
			return array();
		}

		$previous = get_current_user_id();
		wp_set_current_user( 0 );

		$out = array();
		foreach ( (array) wp_get_abilities() as $ability ) {
			if ( ! $ability instanceof WP_Ability || ! $ability->get_meta_item( 'show_in_rest' ) ) {
				continue;
			}
			try {
				$allowed = $ability->check_permissions( null );
			} catch ( Throwable $e ) {
				$allowed = false;
			}
			if ( true === $allowed ) {
				$annotations = (array) $ability->get_meta_item( 'annotations', array() );
				$out[]       = array(
					'name'     => $ability->get_name(),
					'readonly' => ! empty( $annotations['readonly'] ),
				);
			}
		}

		wp_set_current_user( $previous );

		return $out;
	}

	/**
	 * Administrators whose hash predates WordPress 6.8's bcrypt (`$wp$2y$`).
	 *
	 * @return string[] User logins.
	 */
	public static function legacy_hash_admins() {
		$out = array();
		foreach ( get_users( array( 'role' => 'administrator' ) ) as $user ) {
			if ( 0 === strpos( (string) $user->user_pass, '$P$' ) ) {
				$out[] = $user->user_login;
			}
		}
		return $out;
	}

	/**
	 * Which of the eight salt constants are still at the shipped placeholder.
	 *
	 * @return array Constant names.
	 */
	public static function default_salts() {
		$bad = array();

		foreach ( self::SALT_KEYS as $key ) {
			if ( ! defined( $key ) ) {
				$bad[] = $key;
				continue;
			}
			$value = (string) constant( $key );
			if ( 'put your unique phrase here' === $value || strlen( trim( $value ) ) < 32 ) {
				$bad[] = $key;
			}
		}

		return $bad;
	}

	/**
	 * Sensitive files sitting in the web root.
	 *
	 * @return array List of name/size pairs.
	 */
	public static function exposed_files() {
		$found   = array();
		$pattern = '/\.(sql|sql\.gz|sql\.zip|tar|tar\.gz|tgz|wpress|bak|old|save|swp|env)$/i';

		foreach ( (array) @scandir( ABSPATH ) as $entry ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			$path = ABSPATH . $entry;
			if ( ! is_file( $path ) ) {
				continue;
			}

			$is_log = ( 'error_log' === $entry || 'debug.log' === $entry || preg_match( '/\.log$/i', $entry ) );

			if ( $is_log || preg_match( $pattern, $entry ) ) {
				$found[] = array(
					'name' => $entry,
					'size' => (int) @filesize( $path ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				);
			}
		}

		return $found;
	}

	/**
	 * Does a .htaccess file already carry our managed block?
	 *
	 * @param string $file Path to check.
	 * @return bool
	 */
	private static function has_marker( $file ) {
		if ( ! file_exists( $file ) ) {
			return false;
		}
		$contents = (string) @file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		return false !== strpos( $contents, '# BEGIN ' . self::MARKER );
	}

	/* ---------------------------------------------------------------------
	 * Fix dispatcher
	 * ------------------------------------------------------------------ */

	/**
	 * Handle a one-click fix request.
	 *
	 * @return void
	 */
	public function handle_fix() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_harden' );

		// wp-config changes are the owner's call alone.
		$fix = isset( $_POST['fix'] ) ? sanitize_key( wp_unslash( $_POST['fix'] ) ) : '';

		$result = array(
			'ok'  => false,
			'msg' => __( 'إجراء غير معروف.', 'ejabh-security' ),
		);

		switch ( $fix ) {
			case 'regenerate_salts':
				$result = self::regenerate_salts();
				break;
			case 'disallow_file_edit':
				$result = self::set_constant( 'DISALLOW_FILE_EDIT', true );
				break;
			case 'disallow_file_mods':
				$result = self::set_constant( 'DISALLOW_FILE_MODS', true );
				break;
			case 'allow_file_mods':
				$result = self::set_constant( 'DISALLOW_FILE_MODS', false );
				break;
			case 'protect_exposed':
				$result = self::write_root_rules();
				break;
			case 'protect_uploads':
				$result = self::write_uploads_rules();
				break;
			case 'purge_error_log':
				$result = self::purge_error_log();
				break;
			case 'move_ai_keys':
				$result = self::move_ai_keys();
				break;
			case 'gate_abilities':
				Ejabh_Settings::update( array( 'abilities_require_login' => 1 ) );
				$result = array(
					'ok'  => true,
					'msg' => __( 'أصبح تنفيذ القدرات عبر REST يتطلب تسجيل الدخول.', 'ejabh-security' ),
				);
				break;
			case 'delete_exposed':
				$result = self::delete_exposed_file( isset( $_POST['target'] ) ? wp_unslash( $_POST['target'] ) : '' );
				break;
		}

		set_transient( 'dys_sec_harden_result_' . get_current_user_id(), $result, 60 );

		wp_safe_redirect( admin_url( 'admin.php?page=ejabh-security-hardening' ) );
		exit;
	}

	/* ---------------------------------------------------------------------
	 * wp-config.php editing
	 * ------------------------------------------------------------------ */

	/**
	 * Is a string valid PHP?
	 *
	 * @param string $code Source to test.
	 * @return bool
	 */
	private static function syntax_ok( $code ) {
		try {
			token_get_all( $code, TOKEN_PARSE );
			return true;
		} catch ( \ParseError $e ) {
			return false;
		} catch ( \Throwable $e ) {
			return false;
		}
	}

	/**
	 * Write new wp-config content with backup, validation and rollback.
	 *
	 * @param string $new_content Replacement file contents.
	 * @param string $what        Description for the log.
	 * @return array {ok, msg}
	 */
	private static function write_config( $new_content, $what ) {
		$path = self::config_path();

		if ( ! $path ) {
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر العثور على wp-config.php.', 'ejabh-security' ),
			);
		}
		if ( ! is_writable( $path ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'ملف wp-config.php غير قابل للكتابة. ارفع صلاحيته مؤقتاً إلى 644 ثم أعد المحاولة، وأعدها إلى 440 بعد الانتهاء.', 'ejabh-security' ),
			);
		}

		// 1. Validate before touching anything.
		if ( ! self::syntax_ok( $new_content ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'أُلغيت العملية: المحتوى الجديد لم يجتز فحص الصياغة. لم يُعدَّل الملف.', 'ejabh-security' ),
			);
		}

		// 2. The replacement must still define the database connection.
		foreach ( array( 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'DB_HOST' ) as $required ) {
			if ( false === strpos( $new_content, $required ) ) {
				return array(
					'ok'  => false,
					'msg' => __( 'أُلغيت العملية: المحتوى الجديد لا يحتوي على إعدادات قاعدة البيانات. لم يُعدَّل الملف.', 'ejabh-security' ),
				);
			}
		}

		// 3. Back up outside the web-accessible tree.
		$original = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$backup   = self::backup_dir() . '/wp-config-' . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 8, false, false ) . '.bak';

		if ( false === file_put_contents( $backup, $original ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر إنشاء نسخة احتياطية من wp-config.php، فأُلغيت العملية.', 'ejabh-security' ),
			);
		}

		// 4. Write.
		if ( false === file_put_contents( $path, $new_content ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return array(
				'ok'  => false,
				'msg' => __( 'فشلت الكتابة إلى wp-config.php.', 'ejabh-security' ),
			);
		}

		// 5. Verify what actually landed on disk; roll back if it is wrong.
		$written = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( $written !== $new_content || ! self::syntax_ok( $written ) ) {
			file_put_contents( $path, $original ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			return array(
				'ok'  => false,
				'msg' => __( 'المحتوى المكتوب لم يطابق المتوقع، فأُعيد الملف الأصلي من النسخة الاحتياطية.', 'ejabh-security' ),
			);
		}

		Ejabh_Logger::log(
			'wpconfig_modified',
			sprintf( 'عُدِّل wp-config.php: %s. النسخة الاحتياطية: %s', $what, basename( $backup ) ),
			'warning'
		);

		return array(
			'ok'     => true,
			'msg'    => '',
			'backup' => basename( $backup ),
		);
	}

	/**
	 * Escape a value for embedding in a single-quoted PHP string.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function esc_php_single( $value ) {
		return str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $value );
	}

	/**
	 * Replace the first match of a pattern with a literal string.
	 *
	 * preg_replace() interprets `$1`, `${1}` and `\1` inside the *replacement*
	 * as backreferences. Generated salts routinely contain `$` followed by a
	 * digit or brace, which would silently corrupt the value — and can produce
	 * an unparseable config. Using a callback makes the replacement literal.
	 *
	 * @param string $pattern     Regex.
	 * @param string $replacement Literal replacement text.
	 * @param string $subject     Text to operate on.
	 * @param int    $count       Set to the number of replacements made.
	 * @return string|null Null on regex error.
	 */
	private static function replace_literal( $pattern, $replacement, $subject, &$count ) {
		$count = 0;

		$result = preg_replace_callback(
			$pattern,
			static function () use ( $replacement ) {
				return $replacement;
			},
			$subject,
			1,
			$count
		);

		return $result;
	}

	/**
	 * Generate fresh authentication salts and write them.
	 *
	 * @return array {ok, msg}
	 */
	public static function regenerate_salts() {
		$path = self::config_path();
		if ( ! $path ) {
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر العثور على wp-config.php.', 'ejabh-security' ),
			);
		}

		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$missing = array();

		foreach ( self::SALT_KEYS as $key ) {
			// 64 characters including punctuation, generated with random_int().
			$value   = wp_generate_password( 64, true, true );
			$line    = sprintf( "define( '%s', '%s' );", $key, self::esc_php_single( $value ) );
			$pattern = '/^[ \t]*define\(\s*([\'"])' . preg_quote( $key, '/' ) . '\1\s*,\s*([\'"])(?:\\\\.|(?!\2).)*\2\s*\)\s*;[ \t]*$/m';

			$replaced = self::replace_literal( $pattern, $line, $content, $count );

			if ( null === $replaced ) {
				return array(
					'ok'  => false,
					'msg' => __( 'خطأ أثناء معالجة نص wp-config.php. لم يُعدَّل الملف.', 'ejabh-security' ),
				);
			}

			if ( $count ) {
				$content = $replaced;
			} else {
				$missing[ $key ] = $line;
			}
		}

		// Any constant that was absent entirely gets inserted.
		if ( $missing ) {
			$content = self::insert_lines( $content, $missing );
		}

		$result = self::write_config( $content, 'توليد مفاتيح أمان جديدة' );

		if ( $result['ok'] ) {
			$result['msg'] = __( 'تم توليد المفاتيح الثمانية بقيم جديدة. أُبطلت كل الجلسات — سجّل الدخول من جديد.', 'ejabh-security' );
			Ejabh_Logger::log( 'salts_regenerated', 'وُلِّدت مفاتيح أمان جديدة وأُبطلت كل الجلسات.', 'critical' );
		}

		return $result;
	}

	/**
	 * Add, update or remove a boolean constant in wp-config.php.
	 *
	 * @param string $name  Constant name.
	 * @param bool   $value Desired value.
	 * @return array {ok, msg}
	 */
	public static function set_constant( $name, $value ) {
		$path = self::config_path();
		if ( ! $path ) {
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر العثور على wp-config.php.', 'ejabh-security' ),
			);
		}

		$name    = preg_replace( '/[^A-Z_]/', '', strtoupper( $name ) );
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$line    = sprintf( "define( '%s', %s );", $name, $value ? 'true' : 'false' );

		$pattern  = '/^[ \t]*define\(\s*([\'"])' . preg_quote( $name, '/' ) . '\1\s*,\s*[^)]*\)\s*;[ \t]*$/m';
		$replaced = self::replace_literal( $pattern, $line, $content, $count );

		if ( null === $replaced ) {
			return array(
				'ok'  => false,
				'msg' => __( 'خطأ أثناء معالجة نص wp-config.php.', 'ejabh-security' ),
			);
		}

		$content = $count ? $replaced : self::insert_lines( $content, array( $name => $line ) );

		$result = self::write_config( $content, sprintf( '%s = %s', $name, $value ? 'true' : 'false' ) );

		if ( $result['ok'] ) {
			$result['msg'] = sprintf(
				/* translators: 1: constant name, 2: value. */
				__( 'تم ضبط %1$s على %2$s.', 'ejabh-security' ),
				$name,
				$value ? 'true' : 'false'
			);
		}

		return $result;
	}

	/**
	 * Insert define() lines above the "stop editing" marker.
	 *
	 * @param string $content Current file contents.
	 * @param array  $lines   Name => line.
	 * @return string
	 */
	private static function insert_lines( $content, array $lines ) {
		$block = trim( implode( "\n", array_values( $lines ) ), "\n" );

		// The inserted lines can contain `$`, so the matched text is re-emitted
		// from the callback argument rather than through a `$0` backreference.
		$anchor = "/\/\*\s*That's all, stop editing.*?\*\//i";
		if ( preg_match( $anchor, $content ) ) {
			return preg_replace_callback(
				$anchor,
				static function ( $m ) use ( $block ) {
					return $block . "\n\n" . $m[0];
				},
				$content,
				1
			);
		}

		// Fallback: immediately before wp-settings.php is required.
		$require = '/^[ \t]*(require(?:_once)?[ \t]*\(?[ \t]*(?:ABSPATH|__DIR__).*wp-settings\.php.*)$/mi';
		if ( preg_match( $require, $content ) ) {
			return preg_replace_callback(
				$require,
				static function ( $m ) use ( $block ) {
					return $block . "\n\n" . $m[1];
				},
				$content,
				1
			);
		}

		// Last resort: append.
		return rtrim( $content ) . "\n\n" . $block . "\n";
	}

	/* ---------------------------------------------------------------------
	 * .htaccess rules
	 * ------------------------------------------------------------------ */

	/**
	 * Install the protective block in the root .htaccess.
	 *
	 * @return array {ok, msg}
	 */
	public static function write_root_rules() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		$file = ABSPATH . '.htaccess';

		if ( file_exists( $file ) && ! is_writable( $file ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'ملف .htaccess غير قابل للكتابة. غيّر صلاحيته إلى 644 ثم أعد المحاولة.', 'ejabh-security' ),
			);
		}
		if ( ! file_exists( $file ) && ! is_writable( ABSPATH ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'مجلد الموقع غير قابل للكتابة، فتعذّر إنشاء .htaccess.', 'ejabh-security' ),
			);
		}

		// .zip is deliberately absent: a charity site may legitimately offer
		// archives for download, and this block is inherited by every subfolder.
		$rules = array(
			'# منع تنزيل نسخ قواعد البيانات والأرشيفات والسجلات',
			'<FilesMatch "\.(sql|sql\.gz|tar|tar\.gz|tgz|wpress|bak|old|save|swp|log|env|ini)$">',
			'  <IfModule authz_core_module>',
			'    Require all denied',
			'  </IfModule>',
			'  <IfModule !authz_core_module>',
			'    Order allow,deny',
			'    Deny from all',
			'  </IfModule>',
			'</FilesMatch>',
			'',
			'# منع الوصول المباشر لملفات ووردبريس الحسّاسة',
			'<FilesMatch "^(wp-config\.php|wp-config-sample\.php|readme\.html|license\.txt|error_log|debug\.log)$">',
			'  <IfModule authz_core_module>',
			'    Require all denied',
			'  </IfModule>',
			'  <IfModule !authz_core_module>',
			'    Order allow,deny',
			'    Deny from all',
			'  </IfModule>',
			'</FilesMatch>',
			'',
			'# تعطيل فهرسة المجلدات',
			'Options -Indexes',
		);

		if ( ! insert_with_markers( $file, self::MARKER, $rules ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'فشلت الكتابة إلى .htaccess.', 'ejabh-security' ),
			);
		}

		Ejabh_Logger::log( 'htaccess_root_written', 'رُكّبت قواعد الحماية في .htaccess الرئيسي.', 'warning' );

		return array(
			'ok'  => true,
			'msg' => __( 'رُكّبت قواعد الحماية. تحقق من أن الموقع يعمل طبيعياً، وإن حدث خطأ 500 احذف الكتلة الموجودة بين BEGIN/END Ejabh Security.', 'ejabh-security' ),
		);
	}

	/**
	 * Block script execution inside the uploads directory.
	 *
	 * @return array {ok, msg}
	 */
	public static function write_uploads_rules() {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		$uploads = wp_get_upload_dir();
		$dir     = isset( $uploads['basedir'] ) ? $uploads['basedir'] : '';

		if ( ! $dir || ! is_dir( $dir ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر تحديد مجلد الوسائط.', 'ejabh-security' ),
			);
		}

		$file = $dir . '/.htaccess';

		if ( ( file_exists( $file ) && ! is_writable( $file ) ) || ( ! file_exists( $file ) && ! is_writable( $dir ) ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'مجلد الوسائط غير قابل للكتابة.', 'ejabh-security' ),
			);
		}

		$rules = array(
			'# منع تنفيذ أي سكربت داخل مجلد الوسائط',
			'<FilesMatch "\.(?i:php|phtml|php3|php4|php5|php7|php8|phps|pht|phar|cgi|pl|py|jsp|asp|aspx|shtml|sh|htaccess)$">',
			'  <IfModule authz_core_module>',
			'    Require all denied',
			'  </IfModule>',
			'  <IfModule !authz_core_module>',
			'    Order allow,deny',
			'    Deny from all',
			'  </IfModule>',
			'</FilesMatch>',
			'',
			'<IfModule mod_php.c>',
			'  php_flag engine off',
			'</IfModule>',
			'<IfModule mod_php7.c>',
			'  php_flag engine off',
			'</IfModule>',
			'<IfModule mod_php8.c>',
			'  php_flag engine off',
			'</IfModule>',
			'',
			'Options -Indexes',
		);

		if ( ! insert_with_markers( $file, self::MARKER, $rules ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'فشلت الكتابة إلى .htaccess داخل مجلد الوسائط.', 'ejabh-security' ),
			);
		}

		Ejabh_Logger::log( 'htaccess_uploads_written', 'مُنِع تنفيذ PHP داخل مجلد الوسائط.', 'warning' );

		return array(
			'ok'  => true,
			'msg' => __( 'مُنِع تنفيذ PHP داخل uploads. تأكد أن الصور ما زالت تظهر طبيعياً.', 'ejabh-security' ),
		);
	}

	/* ---------------------------------------------------------------------
	 * Exposed files
	 * ------------------------------------------------------------------ */

	/**
	 * Empty the PHP error log and make sure it is blocked.
	 *
	 * @return array {ok, msg}
	 */
	public static function purge_error_log() {
		$file = ABSPATH . 'error_log';

		if ( ! file_exists( $file ) ) {
			return array(
				'ok'  => true,
				'msg' => __( 'لا يوجد سجل أخطاء.', 'ejabh-security' ),
			);
		}
		if ( ! is_writable( $file ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'سجل الأخطاء غير قابل للكتابة.', 'ejabh-security' ),
			);
		}

		$size = (int) filesize( $file );

		// Truncate rather than delete: PHP keeps writing to the same inode, and
		// deleting can leave logging silently broken.
		$handle = fopen( $file, 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen
		if ( false === $handle ) {
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر تفريغ سجل الأخطاء.', 'ejabh-security' ),
			);
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose

		$rules = self::write_root_rules();

		Ejabh_Logger::log(
			'error_log_purged',
			sprintf( 'فُرِّغ سجل الأخطاء (%s) وحُظر الوصول إليه.', size_format( $size ) ),
			'warning'
		);

		return array(
			'ok'  => true,
			'msg' => sprintf(
				/* translators: %s: freed space. */
				__( 'فُرِّغ سجل الأخطاء وحُرِّر %s. %s', 'ejabh-security' ),
				size_format( $size ),
				$rules['ok'] ? __( 'وحُظر الوصول إليه عبر .htaccess.', 'ejabh-security' ) : $rules['msg']
			),
		);
	}

	/**
	 * Delete one exposed file from the web root.
	 *
	 * @param string $name File name (no path).
	 * @return array {ok, msg}
	 */
	public static function delete_exposed_file( $name ) {
		$name = basename( (string) $name );

		// Only files this check itself reported may be removed.
		$allowed = wp_list_pluck( self::exposed_files(), 'name' );
		if ( ! $name || ! in_array( $name, $allowed, true ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'هذا الملف ليس ضمن الملفات المكشوفة المرصودة.', 'ejabh-security' ),
			);
		}

		$path = ABSPATH . $name;
		$real = realpath( $path );

		// Never step outside the web root.
		if ( ! $real || dirname( $real ) !== rtrim( realpath( ABSPATH ), '/\\' ) ) {
			return array(
				'ok'  => false,
				'msg' => __( 'مسار غير صالح.', 'ejabh-security' ),
			);
		}

		$size = (int) @filesize( $real ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		if ( ! @unlink( $real ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink, WordPress.PHP.NoSilencedErrors.Discouraged
			return array(
				'ok'  => false,
				'msg' => __( 'تعذّر حذف الملف — تحقق من الصلاحيات.', 'ejabh-security' ),
			);
		}

		Ejabh_Logger::log(
			'exposed_file_deleted',
			sprintf( 'حُذف ملف مكشوف من جذر الموقع: %s (%s).', $name, size_format( $size ) ),
			'warning'
		);

		return array(
			'ok'  => true,
			'msg' => sprintf(
				/* translators: 1: file name, 2: size. */
				__( 'حُذف %1$s وحُرِّر %2$s.', 'ejabh-security' ),
				$name,
				size_format( $size )
			),
		);
	}
}
