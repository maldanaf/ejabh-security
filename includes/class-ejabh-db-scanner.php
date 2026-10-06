<?php
/**
 * Database scanner.
 *
 * Looks for the three ways a compromise survives in the database rather than on
 * disk: injected code or markup in content, rogue privileged accounts, and
 * tampered configuration. Runs as a small state machine so large content tables
 * do not time out.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Malicious-content and configuration audit for the database.
 */
class Ejabh_DB_Scanner {

	const STATE_OPTION = 'dys_sec_db_scan_state';

	/** Rows read per query. */
	const BATCH = 400;

	/**
	 * Meta keys that legitimately hold large HTML/JSON payloads. Only
	 * critical-severity rules are applied to them to keep the report usable.
	 */
	const NOISY_META_KEYS = array(
		'_elementor_data',
		'_elementor_controls_usage',
		'_elementor_page_settings',
		'_wp_page_template',
		'_oembed_response',
		'_wpforms_form_data',
		'_give_form_settings',
	);

	/**
	 * Ordered list of scan tasks.
	 *
	 * @return array
	 */
	private static function tasks() {
		return array( 'config', 'users', 'roles', 'plugins', 'cron', 'options', 'posts', 'postmeta', 'comments', 'usermeta' );
	}

	/**
	 * Fresh state.
	 *
	 * @return array
	 */
	public static function blank_state() {
		return array(
			'scan_id' => '',
			'status'  => 'idle',
			'task'    => 0,
			'offset'  => 0,
			'rows'    => 0,
			'flagged' => 0,
			'started' => 0,
			'finished'=> 0,
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
	 * Human label for the current task.
	 *
	 * @param int $index Task index.
	 * @return string
	 */
	public static function task_label( $index ) {
		$labels = array(
			'config'   => __( 'إعدادات ووردبريس والتحصين', 'ejabh-security' ),
			'users'    => __( 'الحسابات والصلاحيات', 'ejabh-security' ),
			'roles'    => __( 'تعريفات الأدوار', 'ejabh-security' ),
			'plugins'  => __( 'قائمة الإضافات المُفعّلة', 'ejabh-security' ),
			'cron'     => __( 'المهام المجدولة', 'ejabh-security' ),
			'options'  => __( 'جدول الإعدادات (options)', 'ejabh-security' ),
			'posts'    => __( 'المحتوى (posts)', 'ejabh-security' ),
			'postmeta' => __( 'حقول المحتوى (postmeta)', 'ejabh-security' ),
			'comments' => __( 'التعليقات', 'ejabh-security' ),
			'usermeta' => __( 'بيانات المستخدمين', 'ejabh-security' ),
		);
		$tasks  = self::tasks();
		$key    = isset( $tasks[ $index ] ) ? $tasks[ $index ] : '';
		return isset( $labels[ $key ] ) ? $labels[ $key ] : __( 'اكتمل', 'ejabh-security' );
	}

	/**
	 * Start a new database scan.
	 *
	 * @return array
	 */
	public static function start() {
		Ejabh_Findings::clear_type( 'db' );

		$state            = self::blank_state();
		$state['scan_id'] = substr( md5( uniqid( 'dysdb', true ) ), 0, 16 );
		$state['status']  = 'scanning';
		$state['started'] = time();

		self::save_state( $state );
		Ejabh_Logger::log( 'db_scan_started', 'بدأ فحص قاعدة البيانات.', 'info' );

		return $state;
	}

	/**
	 * Run one batch.
	 *
	 * @return array
	 */
	public static function step() {
		$state = self::state();
		if ( 'scanning' !== $state['status'] ) {
			return $state;
		}

		$tasks    = self::tasks();
		$budget   = max( 3, (int) Ejabh_Settings::get( 'scan_time_budget' ) );
		$deadline = microtime( true ) + $budget;

		while ( microtime( true ) < $deadline ) {
			if ( ! isset( $tasks[ $state['task'] ] ) ) {
				$state['status']   = 'done';
				$state['finished'] = time();

				$counts = Ejabh_Findings::counts( 'db' );
				Ejabh_Logger::log(
					'db_scan_finished',
					sprintf(
						'انتهى فحص قاعدة البيانات: %d صف، %d نتيجة (حرج: %d، عالي: %d).',
						$state['rows'],
						array_sum( $counts ),
						$counts['critical'],
						$counts['high']
					),
					$counts['critical'] > 0 ? 'critical' : 'info'
				);
				break;
			}

			$method = 'task_' . $tasks[ $state['task'] ];
			$done   = self::$method( $state );

			if ( $done ) {
				++$state['task'];
				$state['offset'] = 0;
			}
		}

		self::save_state( $state );
		return $state;
	}

	/**
	 * Abort a running scan.
	 *
	 * @return void
	 */
	public static function cancel() {
		$state           = self::state();
		$state['status'] = 'idle';
		self::save_state( $state );
	}

	/* ---------------------------------------------------------------------
	 * Configuration / hardening audit
	 * ------------------------------------------------------------------ */

	/**
	 * Audit wp-config and site settings.
	 *
	 * @param array $state Scan state (by reference via caller).
	 * @return bool Always true — single pass.
	 */
	private static function task_config( &$state ) {
		$id = $state['scan_id'];

		// Default authentication salts.
		$keys    = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );
		$default = array();
		foreach ( $keys as $key ) {
			if ( ! defined( $key ) ) {
				continue;
			}
			$value = constant( $key );
			if ( 'put your unique phrase here' === $value || '' === trim( (string) $value ) ) {
				$default[] = $key;
			}
		}
		if ( $default ) {
			self::flag(
				$id,
				'critical',
				'config_default_salts',
				__( 'مفاتيح الأمان في wp-config.php لم تُولَّد — ما زالت القيمة الافتراضية', 'ejabh-security' ),
				'wp-config.php',
				sprintf(
					/* translators: %s: comma separated constant names. */
					__( 'المفاتيح التالية قيمتها افتراضية أو فارغة: %s. هذه المفاتيح تُوقّع كوكيز الدخول ورموز CSRF، وكونها معروفة يعني أن توقيع الجلسات قابل للتزوير عند أي تسريب لقاعدة البيانات. ولّد قيماً جديدة من api.wordpress.org/secret-key/1.1/salt/', 'ejabh-security' ),
					implode( ', ', $default )
				)
			);
		}

		// File editing from the dashboard.
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			self::flag(
				$id,
				'high',
				'config_file_edit_allowed',
				__( 'محرر الملفات في لوحة التحكم مفتوح', 'ejabh-security' ),
				'wp-config.php',
				__( 'أي حساب مدير مخترق يستطيع كتابة باب خلفي مباشرة من Appearance → Theme File Editor. أضف: define( \'DISALLOW_FILE_EDIT\', true );', 'ejabh-security' )
			);
		}

		// Open registration with a privileged default role.
		if ( get_option( 'users_can_register' ) ) {
			$role     = (string) get_option( 'default_role' );
			$severity = in_array( $role, array( 'administrator', 'editor' ), true ) ? 'critical' : 'medium';
			self::flag(
				$id,
				$severity,
				'config_open_registration',
				__( 'التسجيل الذاتي مفتوح للزوار', 'ejabh-security' ),
				'wp_options.users_can_register',
				sprintf(
					/* translators: %s: role name. */
					__( 'أي زائر يستطيع إنشاء حساب بدور "%s". أغلق التسجيل إن لم يكن مطلوباً.', 'ejabh-security' ),
					$role
				)
			);
		}

		// Site URL / home URL mismatch or non-HTTPS.
		foreach ( array( 'siteurl', 'home' ) as $opt ) {
			$value = (string) get_option( $opt );
			if ( $value && 0 !== strpos( $value, 'https://' ) ) {
				self::flag(
					$id,
					'medium',
					'config_no_https',
					__( 'عنوان الموقع غير مُهيّأ على HTTPS', 'ejabh-security' ),
					'wp_options.' . $opt,
					sprintf( '%s = %s', $opt, $value )
				);
			}
		}

		// XML-RPC reachable.
		if ( file_exists( ABSPATH . 'xmlrpc.php' ) && ! Ejabh_Settings::get( '2fa_block_xmlrpc' ) ) {
			self::flag(
				$id,
				'medium',
				'config_xmlrpc_open',
				__( 'XML-RPC مفتوح', 'ejabh-security' ),
				'xmlrpc.php',
				__( 'يسمح بتجربة عدد كبير من كلمات المرور في طلب واحد. فعّل حظر XML-RPC من إعدادات هذه الإضافة.', 'ejabh-security' )
			);
		}

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Accounts
	 * ------------------------------------------------------------------ */

	/**
	 * Audit users, with emphasis on privileged accounts.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_users( &$state ) {
		$id     = $state['scan_id'];
		$admins = get_users( array( 'role' => 'administrator' ) );
		$bad    = Ejabh_Signatures::suspicious_email_domains();
		$shapes = Ejabh_Signatures::suspicious_username_patterns();
		$now    = time();

		foreach ( $admins as $user ) {
			++$state['rows'];

			$registered = strtotime( $user->user_registered . ' UTC' );
			$age_days   = $registered ? floor( ( $now - $registered ) / DAY_IN_SECONDS ) : 999;
			$domain     = strtolower( (string) substr( strrchr( (string) $user->user_email, '@' ), 1 ) );

			$reasons = array();

			if ( $domain && in_array( $domain, $bad, true ) ) {
				$reasons[] = sprintf(
					/* translators: %s: e-mail domain. */
					__( 'نطاق البريد "%s" نطاق مؤقت/مزيف يستخدمه المخترقون', 'ejabh-security' ),
					$domain
				);
			}

			foreach ( $shapes as $regex => $why ) {
				if ( preg_match( $regex, $user->user_login ) ) {
					$reasons[] = $why;
					break;
				}
			}

			// A "@google.com" style address that is not actually deliverable is a
			// classic marker: attackers pick a famous domain to look harmless.
			if ( in_array( $domain, array( 'google.com', 'wordpress.org', 'wordpress.com', 'automattic.com', 'example.com', 'test.com' ), true ) ) {
				$reasons[] = sprintf(
					/* translators: %s: e-mail domain. */
					__( 'نطاق البريد "%s" لا يُستخدم لحسابات حقيقية على المواقع', 'ejabh-security' ),
					$domain
				);
			}

			if ( $reasons ) {
				self::flag(
					$id,
					'critical',
					'rogue_admin',
					__( 'حساب مدير مشتبه به بقوة — يُرجَّح أنه من إنشاء المخترق', 'ejabh-security' ),
					sprintf( 'wp_users #%d — %s <%s>', $user->ID, $user->user_login, $user->user_email ),
					sprintf(
						/* translators: 1: reasons, 2: registration date. */
						__( 'الأسباب: %1$s. تاريخ الإنشاء: %2$s. راجع الحساب فوراً واحذفه إن لم يكن معروفاً.', 'ejabh-security' ),
						implode( ' | ', $reasons ),
						$user->user_registered
					)
				);
				continue;
			}

			if ( $age_days <= 30 ) {
				self::flag(
					$id,
					'high',
					'new_admin_account',
					__( 'حساب مدير حديث الإنشاء — يحتاج تأكيداً', 'ejabh-security' ),
					sprintf( 'wp_users #%d — %s <%s>', $user->ID, $user->user_login, $user->user_email ),
					sprintf(
						/* translators: 1: days, 2: date. */
						__( 'أُنشئ قبل %1$d يوم (%2$s). تأكد أن هذا الحساب أنشأه فريقكم.', 'ejabh-security' ),
						(int) $age_days,
						$user->user_registered
					)
				);
			}

			if ( 'admin' === strtolower( $user->user_login ) ) {
				self::flag(
					$id,
					'medium',
					'predictable_admin_username',
					__( 'اسم المستخدم "admin" قابل للتنبؤ', 'ejabh-security' ),
					sprintf( 'wp_users #%d — %s', $user->ID, $user->user_login ),
					__( 'يمنح المخترق نصف المعلومة مجاناً. أنشئ حساب مدير باسم آخر ثم انقل الملكية.', 'ejabh-security' )
				);
			}
		}

		// WordPress still accepts a bare MD5 in user_pass and silently upgrades
		// it at the next login. Nothing in WordPress writes one, but
		// `UPDATE wp_users SET user_pass = MD5('x')` is the standard way to
		// plant or hijack an account straight through SQL.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$md5_users = $wpdb->get_results( "SELECT ID, user_login, user_email FROM {$wpdb->users} WHERE user_pass REGEXP '^[a-fA-F0-9]{32}$' LIMIT 50" );
		foreach ( (array) $md5_users as $row ) {
			$is_admin = user_can( (int) $row->ID, 'manage_options' );
			self::flag(
				$id,
				$is_admin ? 'critical' : 'high',
				'md5_password_hash',
				$is_admin
					? __( 'كلمة مرور مدير مكتوبة مباشرة في قاعدة البيانات (MD5) — بصمة حساب مخترق عبر SQL', 'ejabh-security' )
					: __( 'كلمة مرور مكتوبة مباشرة في قاعدة البيانات (MD5)', 'ejabh-security' ),
				sprintf( 'wp_users #%d — %s <%s>', $row->ID, $row->user_login, $row->user_email ),
				__( 'ووردبريس لا يُنتج هذا الشكل أبداً؛ يظهر فقط عندما تُكتب كلمة المرور بأمر SQL مباشر.', 'ejabh-security' )
			);
		}

		$count = count( $admins );
		if ( $count > 3 ) {
			self::flag(
				$id,
				'medium',
				'too_many_admins',
				__( 'عدد حسابات المدير أكبر من اللازم', 'ejabh-security' ),
				'wp_users',
				sprintf(
					/* translators: %d: number of administrators. */
					__( 'يوجد %d حساب بصلاحية مدير. كل حساب إضافي هو باب دخول إضافي — أنزل غير الضروري إلى دور أقل.', 'ejabh-security' ),
					$count
				)
			);
		}

		return true;
	}

	/**
	 * Audit role definitions for privilege escalation.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_roles( &$state ) {
		$id        = $state['scan_id'];
		$dangerous = array( 'install_plugins', 'edit_plugins', 'activate_plugins', 'edit_themes', 'edit_files', 'unfiltered_upload', 'edit_users', 'promote_users', 'manage_options' );
		$roles     = wp_roles();

		foreach ( $roles->roles as $slug => $role ) {
			++$state['rows'];

			if ( 'administrator' === $slug ) {
				continue;
			}

			$granted = array();
			foreach ( $dangerous as $cap ) {
				if ( ! empty( $role['capabilities'][ $cap ] ) ) {
					$granted[] = $cap;
				}
			}

			if ( $granted ) {
				self::flag(
					$id,
					'high',
					'role_privilege_escalation',
					__( 'دور غير المدير يملك صلاحيات خطيرة', 'ejabh-security' ),
					sprintf( 'wp_user_roles → %s', $slug ),
					sprintf(
						/* translators: 1: role name, 2: capability list. */
						__( 'الدور "%1$s" يملك: %2$s. هذه إحدى طرق المخترق للاحتفاظ بصلاحيات بعد حذف حسابه.', 'ejabh-security' ),
						$slug,
						implode( ', ', $granted )
					)
				);
			}
		}

		return true;
	}

	/**
	 * Check the active plugin list against what is actually installed.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_plugins( &$state ) {
		$id      = $state['scan_id'];
		$active  = (array) get_option( 'active_plugins', array() );
		$blocked = array_map( 'strtolower', (array) Ejabh_Settings::get( 'guard_blocked_slugs' ) );

		foreach ( $active as $plugin ) {
			++$state['rows'];
			$slug = strtolower( strtok( (string) $plugin, '/' ) );

			if ( in_array( $slug, $blocked, true ) ) {
				self::flag(
					$id,
					'critical',
					'blocked_plugin_active',
					__( 'إضافة محظورة مُدرجة كمُفعّلة', 'ejabh-security' ),
					sprintf( 'wp_options.active_plugins → %s', $plugin ),
					__( 'هذه الإضافة على قائمة الحظر (مدير ملفات). احذف السجل من active_plugins وتأكد من إزالة مجلدها.', 'ejabh-security' )
				);
				continue;
			}

			if ( ! file_exists( WP_PLUGIN_DIR . '/' . $plugin ) ) {
				self::flag(
					$id,
					'high',
					'ghost_active_plugin',
					__( 'إضافة مُدرجة كمُفعّلة لكن ملفاتها غير موجودة', 'ejabh-security' ),
					sprintf( 'wp_options.active_plugins → %s', $plugin ),
					__( 'السجل باقٍ في قاعدة البيانات بعد حذف الملفات. هذا يدل على أن الإضافة كانت شغّالة سابقاً — وإن كانت مصابة فهي على الأرجح مسار الاختراق. نظّف السجل.', 'ejabh-security' )
				);
			}
		}

		return true;
	}

	/**
	 * Audit scheduled tasks.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_cron( &$state ) {
		$id   = $state['scan_id'];
		$cron = get_option( 'cron' );

		if ( ! is_array( $cron ) ) {
			return true;
		}

		foreach ( $cron as $timestamp => $hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}
			foreach ( $hooks as $hook => $events ) {
				++$state['rows'];

				$suspicious = preg_match( '/^[a-f0-9]{16,}$/i', $hook )
					|| preg_match( '/\b(?:eval|base64|shell|exec|backdoor|payload|inject)\b/i', $hook );

				if ( ! $suspicious ) {
					continue;
				}

				self::flag(
					$id,
					'critical',
					'suspicious_cron',
					__( 'مهمة مجدولة باسم مشبوه — وسيلة شائعة لإعادة زرع الباب الخلفي', 'ejabh-security' ),
					sprintf( 'wp_options.cron → %s', $hook ),
					sprintf(
						/* translators: %s: scheduled time. */
						__( 'موعد التنفيذ: %s. المهام المجدولة تعمل تلقائياً، فتُستخدم لإعادة إنشاء الملفات المحذوفة.', 'ejabh-security' ),
						gmdate( 'Y-m-d H:i', (int) $timestamp )
					)
				);
			}
		}

		return true;
	}

	/* ---------------------------------------------------------------------
	 * Content tables
	 * ------------------------------------------------------------------ */

	/**
	 * Scan wp_options.
	 *
	 * @param array $state Scan state.
	 * @return bool True when the table is exhausted.
	 */
	private static function task_options( &$state ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_id, option_name, option_value, autoload FROM {$wpdb->options} ORDER BY option_id ASC LIMIT %d OFFSET %d",
				self::BATCH,
				(int) $state['offset']
			)
		);

		if ( ! $rows ) {
			return true;
		}

		foreach ( $rows as $row ) {
			++$state['rows'];

			$value  = (string) $row->option_value;
			$noisy  = self::is_plugin_option( $row->option_name );
			$target = sprintf( 'wp_options.%s (autoload=%s)', $row->option_name, $row->autoload );

			// Snippet plugins store PHP in the database by design. Reporting
			// that as critical is wrong — the question is whether the snippet is
			// yours, so it is downgraded and the guidance says exactly that.
			$snippet_store = self::is_snippet_store( $row->option_name );

			$state['flagged'] += self::match_value(
				$state['scan_id'],
				$value,
				$target,
				$noisy ? 'critical' : '',
				$snippet_store
			);

			// Serialized PHP objects in options are an object-injection gadget.
			if ( preg_match( '/(?:^|;|\{)O:\d+:"/', $value ) ) {
				self::flag(
					$state['scan_id'],
					'high',
					'db_serialized_object',
					__( 'كائن PHP مُسلسل مخزّن في الإعدادات (خطر PHP Object Injection)', 'ejabh-security' ),
					$target,
					substr( $value, 0, 400 )
				);
				++$state['flagged'];
			}
		}

		$state['offset'] += self::BATCH;
		return count( $rows ) < self::BATCH;
	}

	/**
	 * Scan wp_posts.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_posts( &$state ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_title, post_content, post_type, post_status FROM {$wpdb->posts} ORDER BY ID ASC LIMIT %d OFFSET %d",
				self::BATCH,
				(int) $state['offset']
			)
		);

		if ( ! $rows ) {
			return true;
		}

		foreach ( $rows as $row ) {
			++$state['rows'];
			$target = sprintf( 'wp_posts #%d (%s/%s) — %s', $row->ID, $row->post_type, $row->post_status, wp_html_excerpt( $row->post_title, 60 ) );
			$state['flagged'] += self::match_value( $state['scan_id'], (string) $row->post_content, $target );
		}

		$state['offset'] += self::BATCH;
		return count( $rows ) < self::BATCH;
	}

	/**
	 * Scan wp_postmeta.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_postmeta( &$state ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT meta_id, post_id, meta_key, meta_value FROM {$wpdb->postmeta} ORDER BY meta_id ASC LIMIT %d OFFSET %d",
				self::BATCH,
				(int) $state['offset']
			)
		);

		if ( ! $rows ) {
			return true;
		}

		foreach ( $rows as $row ) {
			++$state['rows'];

			$only = in_array( $row->meta_key, self::NOISY_META_KEYS, true ) ? 'critical' : '';
			$target = sprintf( 'wp_postmeta #%d (post %d) → %s', $row->meta_id, $row->post_id, $row->meta_key );
			$state['flagged'] += self::match_value( $state['scan_id'], (string) $row->meta_value, $target, $only );
		}

		$state['offset'] += self::BATCH;
		return count( $rows ) < self::BATCH;
	}

	/**
	 * Scan wp_comments.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_comments( &$state ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT comment_ID, comment_content, comment_author_url, comment_approved FROM {$wpdb->comments} ORDER BY comment_ID ASC LIMIT %d OFFSET %d",
				self::BATCH,
				(int) $state['offset']
			)
		);

		if ( ! $rows ) {
			return true;
		}

		foreach ( $rows as $row ) {
			++$state['rows'];
			$target = sprintf( 'wp_comments #%d (approved=%s)', $row->comment_ID, $row->comment_approved );
			$state['flagged'] += self::match_value( $state['scan_id'], (string) $row->comment_content . ' ' . (string) $row->comment_author_url, $target );
		}

		$state['offset'] += self::BATCH;
		return count( $rows ) < self::BATCH;
	}

	/**
	 * Scan wp_usermeta for stored payloads.
	 *
	 * @param array $state Scan state.
	 * @return bool
	 */
	private static function task_usermeta( &$state ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT umeta_id, user_id, meta_key, meta_value FROM {$wpdb->usermeta} WHERE meta_key NOT IN ('session_tokens') ORDER BY umeta_id ASC LIMIT %d OFFSET %d",
				self::BATCH,
				(int) $state['offset']
			)
		);

		if ( ! $rows ) {
			return true;
		}

		foreach ( $rows as $row ) {
			++$state['rows'];
			$target = sprintf( 'wp_usermeta #%d (user %d) → %s', $row->umeta_id, $row->user_id, $row->meta_key );
			$state['flagged'] += self::match_value( $state['scan_id'], (string) $row->meta_value, $target, 'critical' );
		}

		$state['offset'] += self::BATCH;
		return count( $rows ) < self::BATCH;
	}

	/* ---------------------------------------------------------------------
	 * Matching helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Apply the database rules to one value.
	 *
	 * @param string $scan_id       Scan identifier.
	 * @param string $value         Value to inspect.
	 * @param string $target        Human-readable location.
	 * @param string $min_severity  When set, only rules of this severity run.
	 * @param bool   $snippet_store Whether this row legitimately holds code.
	 * @return int Findings recorded.
	 */
	private static function match_value( $scan_id, $value, $target, $min_severity = '', $snippet_store = false ) {
		if ( '' === $value || strlen( $value ) < 8 ) {
			return 0;
		}

		$hits = 0;

		foreach ( Ejabh_Signatures::db_patterns() as $rule ) {
			if ( $min_severity && $rule['severity'] !== $min_severity ) {
				continue;
			}
			if ( ! preg_match( $rule['regex'], $value, $m, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}

			$severity = $rule['severity'];

			// Code inside a snippet plugin's own storage is expected. It still
			// gets reported (an attacker can add a snippet too), but as
			// something to confirm rather than an emergency.
			if ( $snippet_store && in_array( $rule['id'], array( 'db_php_code', 'db_eval', 'db_base64_blob', 'db_external_script', 'db_iframe' ), true ) ) {
				$severity = 'medium';
			}

			// Embeds and scripts pointing at known-good hosts are not findings.
			// Surviving the gate means the host is *not* trusted, which is a
			// stronger signal than the generic rule severity implies.
			if ( in_array( $rule['id'], array( 'db_iframe', 'db_external_script' ), true ) ) {
				if ( self::only_trusted_hosts( $value, $rule['id'] ) ) {
					continue;
				}
				$severity = 'high';
			}

			$offset  = isset( $m[0][1] ) ? (int) $m[0][1] : 0;
			$excerpt = trim( preg_replace( '/\s+/', ' ', substr( $value, max( 0, $offset - 100 ), 400 ) ) );

			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'db',
					'severity'  => $severity,
					'rule'      => $rule['id'],
					'title'     => $rule['title'],
					'target'    => $target,
					'snippet'   => $excerpt,
				)
			);
			++$hits;
		}

		return $hits;
	}

	/**
	 * Are all embedded hosts in this value on the trusted list?
	 *
	 * @param string $value   Value to inspect.
	 * @param string $rule_id Which rule is asking.
	 * @return bool
	 */
	private static function only_trusted_hosts( $value, $rule_id ) {
		$tag     = 'db_iframe' === $rule_id ? 'iframe' : 'script';
		$trusted = array_map( 'strtolower', Ejabh_Signatures::trusted_hosts() );

		if ( ! preg_match_all( '#<' . $tag . '[^>]{0,400}?\bsrc\s*=\s*[\'"]?([^\'"\s>]+)#i', $value, $matches ) ) {
			// An iframe with no src at all is not an exfiltration channel.
			return 'db_iframe' === $rule_id;
		}

		foreach ( $matches[1] as $src ) {
			$src = html_entity_decode( $src, ENT_QUOTES );
			if ( 0 === strpos( $src, '//' ) ) {
				$src = 'https:' . $src;
			}

			$host = wp_parse_url( $src, PHP_URL_HOST );
			if ( ! $host ) {
				// Relative or inline source — same origin.
				continue;
			}

			$host    = strtolower( $host );
			$allowed = false;
			foreach ( $trusted as $ok ) {
				if ( $host === $ok || substr( $host, -strlen( '.' . $ok ) ) === '.' . $ok ) {
					$allowed = true;
					break;
				}
			}
			if ( ! $allowed ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Is this option the storage of a plugin whose whole job is holding code?
	 *
	 * WPCode, Code Snippets and the header/footer injectors all keep PHP, JS and
	 * CSS in wp_options as their normal operation.
	 *
	 * @param string $name Option name.
	 * @return bool
	 */
	private static function is_snippet_store( $name ) {
		$known = array(
			'wpcode_snippets',
			'wpcode_global_header',
			'wpcode_global_footer',
			'wpcode_global_body',
			'ihaf_insert_header',
			'ihaf_insert_footer',
			'ihaf_insert_body',
			'code_snippets_settings',
			'custom_css_post_id',
		);

		if ( in_array( $name, $known, true ) ) {
			return true;
		}

		foreach ( array( 'wpcode_', 'ihaf_', 'code_snippets_', 'csshero_', 'simple_custom_css' ) as $prefix ) {
			if ( 0 === strpos( $name, $prefix ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Does this option belong to a known plugin that stores large blobs?
	 *
	 * @param string $name Option name.
	 * @return bool
	 */
	private static function is_plugin_option( $name ) {
		$prefixes = array(
			'_transient_',
			'_site_transient_',
			'rocket_',
			'wp_rocket_',
			'elementor_',
			'wpforms_',
			'aioseo_',
			'give_',
			'woocommerce_',
			'wc_',
			'trp_',
			'monsterinsights_',
			'action_scheduler_',
			'breadcrumb_navxt',
			'akismet_',
			'ai1wm_',
			'cmb2_',
			'widget_',
			'theme_mods_',
		);

		foreach ( $prefixes as $prefix ) {
			if ( 0 === strpos( $name, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Shorthand for recording a database finding.
	 *
	 * @param string $scan_id  Scan identifier.
	 * @param string $severity Severity.
	 * @param string $rule     Rule ID.
	 * @param string $title    Finding title.
	 * @param string $target   Location.
	 * @param string $snippet  Detail.
	 * @return void
	 */
	private static function flag( $scan_id, $severity, $rule, $title, $target, $snippet ) {
		Ejabh_Findings::add(
			array(
				'scan_id'   => $scan_id,
				'scan_type' => 'db',
				'severity'  => $severity,
				'rule'      => $rule,
				'title'     => $title,
				'target'    => $target,
				'snippet'   => $snippet,
			)
		);
	}
}
