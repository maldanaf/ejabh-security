<?php
/**
 * Admin screens.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Menus, assets and form handling for the admin area.
 */
class Ejabh_Admin {

	const MENU = 'ejabh-security';

	/**
	 * Plugin container.
	 *
	 * @var Ejabh_Plugin
	 */
	private $plugin;

	/**
	 * Constructor.
	 *
	 * @param Ejabh_Plugin $plugin Plugin container.
	 */
	public function __construct( Ejabh_Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( 'admin_post_dys_sec_save_settings', array( $this, 'save_settings' ) );
		add_action( 'admin_post_dys_sec_finding_status', array( $this, 'finding_status' ) );
		add_action( 'admin_post_dys_sec_unblock_ip', array( $this, 'unblock_ip' ) );
		add_action( 'admin_post_dys_sec_reset_fim', array( $this, 'reset_fim' ) );
		add_action( 'admin_post_dys_sec_clear_findings', array( $this, 'clear_findings' ) );
		add_action( 'admin_post_dys_sec_test_report', array( $this, 'test_report' ) );
		add_action( 'admin_post_dys_sec_watch_release', array( $this, 'watch_release' ) );
		add_action( 'admin_bar_menu', array( $this, 'admin_bar' ), 100 );
	}

	/**
	 * Register the menu tree.
	 *
	 * @return void
	 */
	public function menu() {
		$counts   = Ejabh_Findings::counts();
		$critical = (int) $counts['critical'] + (int) $counts['high'];
		$bubble   = $critical ? ' <span class="update-plugins count-' . $critical . '"><span class="plugin-count">' . number_format_i18n( $critical ) . '</span></span>' : '';

		add_menu_page(
			__( 'حماية الموقع', 'ejabh-security' ),
			__( 'حماية الموقع', 'ejabh-security' ) . $bubble,
			'manage_options',
			self::MENU,
			array( $this, 'render_dashboard' ),
			'dashicons-shield-alt',
			2
		);

		$pages = array(
			self::MENU                 => __( 'لوحة الحماية', 'ejabh-security' ),
			self::MENU . '-sessions'   => __( 'الجلسات النشطة', 'ejabh-security' ),
			self::MENU . '-files'      => __( 'فحص الملفات', 'ejabh-security' ),
			self::MENU . '-database'   => __( 'فحص قاعدة البيانات', 'ejabh-security' ),
			self::MENU . '-integrity'  => __( 'نزاهة الإضافات', 'ejabh-security' ),
			self::MENU . '-hardening'  => __( 'التحصين', 'ejabh-security' ),
			self::MENU . '-quarantine' => __( 'الحجر والحظر', 'ejabh-security' ),
			self::MENU . '-log'        => __( 'سجل الأحداث', 'ejabh-security' ),
			self::MENU . '-settings'   => __( 'الإعدادات', 'ejabh-security' ),
		);

		$callbacks = array(
			self::MENU                 => 'render_dashboard',
			self::MENU . '-sessions'   => 'render_sessions',
			self::MENU . '-files'      => 'render_files',
			self::MENU . '-database'   => 'render_database',
			self::MENU . '-integrity'  => 'render_integrity',
			self::MENU . '-hardening'  => 'render_hardening',
			self::MENU . '-quarantine' => 'render_quarantine',
			self::MENU . '-log'        => 'render_log',
			self::MENU . '-settings'   => 'render_settings',
		);

		foreach ( $pages as $slug => $title ) {
			add_submenu_page(
				self::MENU,
				$title,
				$title,
				'manage_options',
				$slug,
				array( $this, $callbacks[ $slug ] )
			);
		}
	}

	/**
	 * Enqueue styles and scripts on our screens only.
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public function assets( $hook ) {
		if ( false === strpos( (string) $hook, self::MENU ) ) {
			return;
		}

		wp_enqueue_style(
			'ejabh-sec-admin',
			EJABH_SEC_URL . 'assets/css/admin.css',
			array(),
			EJABH_SEC_VERSION
		);

		wp_enqueue_script(
			'ejabh-sec-admin',
			EJABH_SEC_URL . 'assets/js/admin.js',
			array(),
			EJABH_SEC_VERSION,
			array(
				'in_footer' => true,
				'strategy'  => 'defer',
			)
		);

		wp_localize_script(
			'ejabh-sec-admin',
			'ejabhSec',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'dys_sec_scan' ),
				'i18n'    => array(
					'starting'  => __( 'جارٍ البدء…', 'ejabh-security' ),
					'scanning'  => __( 'جارٍ الفحص…', 'ejabh-security' ),
					'cancelled' => __( 'أُلغي الفحص.', 'ejabh-security' ),
					'failed'    => __( 'تعذّر إكمال الفحص. حدّث الصفحة وأعد المحاولة.', 'ejabh-security' ),
					'confirm'   => __( 'سيبدأ فحص جديد وتُحذف نتائج الفحص السابق. متابعة؟', 'ejabh-security' ),
					'reload'    => __( 'اكتمل الفحص. جارٍ تحديث النتائج…', 'ejabh-security' ),
				),
			)
		);
	}

	/**
	 * Show a red shield in the toolbar when something critical is open.
	 *
	 * @param WP_Admin_Bar $bar Admin bar instance.
	 * @return void
	 */
	public function admin_bar( $bar ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$counts = Ejabh_Findings::counts();
		if ( ! $counts['critical'] ) {
			return;
		}

		$bar->add_node(
			array(
				'id'    => 'ejabh-sec-alert',
				'title' => '⚠ ' . sprintf(
					/* translators: %s: number of critical findings. */
					__( '%s نتيجة حرجة', 'ejabh-security' ),
					number_format_i18n( $counts['critical'] )
				),
				'href'  => admin_url( 'admin.php?page=' . self::MENU ),
				'meta'  => array( 'class' => 'ejabh-sec-alert-node' ),
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * Form handlers
	 * ------------------------------------------------------------------ */

	/**
	 * Persist the settings form.
	 *
	 * @return void
	 */
	public function save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_settings' );

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$post = wp_unslash( $_POST );
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		$bools = array(
			'2fa_enabled',
			'2fa_fail_open',
			'2fa_block_xmlrpc',
			'2fa_block_app_pw',
			'guard_enabled',
			'guard_autodelete',
			'caps_enabled',
			'caps_lock_plugins',
			'caps_lock_themes',
			'caps_lock_file_edit',
			'notify_on_critical',
			'integrity_enabled',
			'fim_enabled',
			'fim_alert_new_php',
			'admin_guard_enabled',
			'admin_guard_revert',
			'login_limit_enabled',
			'new_ip_alert_enabled',
			'enum_block_enabled',
			'quarantine_enabled',
			'sched_scan_enabled',
			'clean_admin_enabled',
			'upload_guard_enabled',
			'watch_enabled',
			'report_daily_enabled',
			'abilities_require_login',
			'auto_update_self',
		);

		$values = array();
		foreach ( $bools as $key ) {
			$values[ $key ] = empty( $post[ $key ] ) ? 0 : 1;
		}

		$values['2fa_code_length']    = max( 4, min( 10, (int) ( $post['2fa_code_length'] ?? 6 ) ) );
		$values['2fa_code_ttl']       = max( 60, min( 3600, (int) ( $post['2fa_code_ttl'] ?? 600 ) ) );
		$values['2fa_max_attempts']   = max( 1, min( 20, (int) ( $post['2fa_max_attempts'] ?? 5 ) ) );
		$values['2fa_resend_wait']    = max( 15, min( 600, (int) ( $post['2fa_resend_wait'] ?? 60 ) ) );
		$values['scan_time_budget']   = max( 3, min( 60, (int) ( $post['scan_time_budget'] ?? 12 ) ) );
		$values['scan_max_file_size'] = max( 65536, min( 33554432, (int) ( $post['scan_max_file_size'] ?? 3145728 ) ) );

		$owner = (int) ( $post['caps_owner_id'] ?? 0 );
		if ( $owner && user_can( $owner, 'manage_options' ) ) {
			$values['caps_owner_id'] = $owner;
		}

		$invalid                 = array();
		$values['notify_emails'] = Ejabh_Settings::parse_email_list( (string) ( $post['notify_emails'] ?? '' ), $invalid );
		// Keep the legacy single-address field pointing at the first recipient,
		// in case this version is ever rolled back.
		$values['notify_email'] = $values['notify_emails'] ? $values['notify_emails'][0] : '';
		set_transient( 'dys_sec_invalid_emails_' . get_current_user_id(), array_slice( $invalid, 0, 20 ), 60 );

		$values['report_daily_hour'] = max( 0, min( 23, (int) ( $post['report_daily_hour'] ?? 8 ) ) );

		$action                 = (string) ( $post['watch_action'] ?? 'quarantine' );
		$values['watch_action'] = in_array( $action, array( 'quarantine', 'neutralize', 'report' ), true ) ? $action : 'quarantine';

		$values['login_max_attempts'] = max( 1, min( 50, (int) ( $post['login_max_attempts'] ?? 5 ) ) );
		$values['login_lockout_mins'] = max( 1, min( 1440, (int) ( $post['login_lockout_mins'] ?? 30 ) ) );
		$values['login_window_mins']  = max( 1, min( 1440, (int) ( $post['login_window_mins'] ?? 15 ) ) );

		$freq                     = (string) ( $post['sched_scan_freq'] ?? 'weekly' );
		$values['sched_scan_freq'] = in_array( $freq, array( 'daily', 'weekly' ), true ) ? $freq : 'weekly';

		$values['2fa_exempt_user_ids'] = $this->parse_id_list( (string) ( $post['2fa_exempt_user_ids'] ?? '' ) );
		$values['guard_blocked_slugs'] = $this->parse_slug_list( (string) ( $post['guard_blocked_slugs'] ?? '' ) );
		$values['guard_blocked_files'] = $this->parse_file_list( (string) ( $post['guard_blocked_files'] ?? '' ) );
		$values['scan_skip_dirs']      = $this->parse_path_list( (string) ( $post['scan_skip_dirs'] ?? '' ) );
		$values['login_ip_allowlist']  = $this->parse_ip_list( (string) ( $post['login_ip_allowlist'] ?? '' ) );

		$roles                        = isset( $post['new_ip_alert_roles'] ) ? (array) $post['new_ip_alert_roles'] : array();
		$values['new_ip_alert_roles'] = array_values( array_intersect( array_map( 'sanitize_key', $roles ), array_keys( wp_roles()->roles ) ) );

		Ejabh_Settings::update( $values );

		// Cron intervals and the report hour may have changed.
		Ejabh_Scheduler::reschedule();
		Ejabh_Watcher::reschedule();
		Ejabh_Daily_Report::reschedule();

		Ejabh_Logger::log( 'settings_saved', 'تم تحديث إعدادات الحماية.', 'warning' );

		wp_safe_redirect( add_query_arg( 'dys_notice', 'saved', admin_url( 'admin.php?page=' . self::MENU . '-settings' ) ) );
		exit;
	}

	/**
	 * Mark a finding reviewed or reopen it.
	 *
	 * @return void
	 */
	public function finding_status() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_finding' );

		$id     = isset( $_POST['finding_id'] ) ? (int) $_POST['finding_id'] : 0;
		$status = isset( $_POST['status'] ) ? sanitize_key( wp_unslash( $_POST['status'] ) ) : '';
		$back   = isset( $_POST['back'] ) ? sanitize_key( wp_unslash( $_POST['back'] ) ) : self::MENU;

		if ( $id && $status ) {
			Ejabh_Findings::set_status( $id, $status );
			Ejabh_Logger::log( 'finding_status', sprintf( 'النتيجة #%d صارت "%s".', $id, $status ), 'info' );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=' . $back ) );
		exit;
	}

	/**
	 * Lift a login block on an IP.
	 *
	 * @return void
	 */
	public function unblock_ip() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_quarantine' );

		$ip = isset( $_POST['ip'] ) ? wp_unslash( $_POST['ip'] ) : '';
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );

		if ( $ip ) {
			Ejabh_Login_Limiter::unblock( $ip );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::MENU . '-quarantine' ) );
		exit;
	}

	/**
	 * Wipe the findings log so a fresh scan starts from nothing.
	 *
	 * @return void
	 */
	public function clear_findings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_clear_findings' );

		$kind = isset( $_POST['kind'] ) ? sanitize_key( wp_unslash( $_POST['kind'] ) ) : '';
		$back = isset( $_POST['back'] ) ? sanitize_key( wp_unslash( $_POST['back'] ) ) : self::MENU;

		if ( in_array( $kind, array( 'file', 'db', 'integrity' ), true ) ) {
			Ejabh_Findings::clear_type( $kind );
			$removed = $kind;
		} else {
			Ejabh_Findings::clear_all();
			$removed = 'all';
		}

		Ejabh_Logger::log( 'findings_cleared', sprintf( 'مُسح سجل النتائج (%s).', $removed ), 'info' );

		wp_safe_redirect( admin_url( 'admin.php?page=' . $back ) );
		exit;
	}

	/**
	 * Send the daily report now, to every saved recipient.
	 *
	 * @return void
	 */
	public function test_report() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_test_report' );

		$results = Ejabh_Daily_Report::deliver( true );
		set_transient( 'dys_sec_test_report_' . get_current_user_id(), $results, 120 );

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::MENU . '-settings' ) );
		exit;
	}

	/**
	 * Let the watcher act automatically again after a burst was reviewed.
	 *
	 * @return void
	 */
	public function watch_release() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_watch_release' );

		Ejabh_Watcher::release_hold();
		Ejabh_Logger::log( 'watch_released', 'أُعيد تفعيل الإجراءات التلقائية لمراقب الملفات بعد المراجعة.', 'warning' );

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::MENU ) );
		exit;
	}

	/**
	 * Discard the file-change baseline.
	 *
	 * @return void
	 */
	public function reset_fim() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_reset_fim' );

		Ejabh_FIM::reset();

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::MENU . '-files' ) );
		exit;
	}

	/**
	 * Parse a textarea of user IDs.
	 *
	 * @param string $raw Raw input.
	 * @return array
	 */
	private function parse_id_list( $raw ) {
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		$ids   = array_map( 'absint', (array) $parts );
		return array_values( array_unique( array_filter( $ids ) ) );
	}

	/**
	 * Parse a textarea of plugin slugs.
	 *
	 * @param string $raw Raw input.
	 * @return array
	 */
	private function parse_slug_list( $raw ) {
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		$out   = array();
		foreach ( (array) $parts as $part ) {
			$slug = sanitize_key( $part );
			if ( $slug ) {
				$out[] = $slug;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Parse a textarea of file names.
	 *
	 * @param string $raw Raw input.
	 * @return array
	 */
	private function parse_file_list( $raw ) {
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		$out   = array();
		foreach ( (array) $parts as $part ) {
			$name = sanitize_file_name( $part );
			if ( $name ) {
				$out[] = strtolower( $name );
			}
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * Parse a textarea of IPs, prefixes and CIDR ranges.
	 *
	 * @param string $raw Raw input.
	 * @return array
	 */
	private function parse_ip_list( $raw ) {
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		$out   = array();

		foreach ( (array) $parts as $part ) {
			$entry = trim( $part );
			if ( '' === $entry ) {
				continue;
			}
			// Accept a plain IP, a trailing-dot prefix, or CIDR notation.
			if ( filter_var( $entry, FILTER_VALIDATE_IP ) || preg_match( '#^\d{1,3}(\.\d{1,3}){0,2}\.$#', $entry ) || preg_match( '#^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$#', $entry ) ) {
				$out[] = $entry;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Parse a textarea of relative paths.
	 *
	 * @param string $raw Raw input.
	 * @return array
	 */
	private function parse_path_list( $raw ) {
		$lines = preg_split( '/[\r\n,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		$out   = array();
		foreach ( (array) $lines as $line ) {
			$path = trim( $line );
			$path = ltrim( str_replace( array( '..', '\\' ), array( '', '/' ), $path ), '/' );
			if ( $path ) {
				$out[] = $path;
			}
		}
		return array_values( array_unique( $out ) );
	}

	/* ---------------------------------------------------------------------
	 * Views
	 * ------------------------------------------------------------------ */

	/**
	 * Include a view file.
	 *
	 * @param string $view View slug.
	 * @param array  $vars Variables to extract into scope.
	 * @return void
	 */
	private function view( $view, array $vars = array() ) {
		$file = EJABH_SEC_DIR . 'admin/views/' . $view . '.php';
		if ( ! file_exists( $file ) ) {
			return;
		}
		$admin = $this; // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// phpcs:ignore WordPress.PHP.DontExtract.extract_extract
		extract( $vars, EXTR_SKIP );
		include $file;
	}

	/**
	 * Dashboard.
	 *
	 * @return void
	 */
	public function render_dashboard() {
		$this->view(
			'dashboard',
			array(
				'counts'      => Ejabh_Findings::counts(),
				'file_counts' => Ejabh_Findings::counts( 'file' ),
				'db_counts'   => Ejabh_Findings::counts( 'db' ),
				'sessions'    => Ejabh_Sessions::summary(),
				'file_state'  => Ejabh_File_Scanner::state(),
				'db_state'    => Ejabh_DB_Scanner::state(),
				'top'         => Ejabh_Findings::get( '', 12 ),
				'log'         => Ejabh_Logger::recent( 10 ),
			)
		);
	}

	/**
	 * Active sessions.
	 *
	 * @return void
	 */
	public function render_sessions() {
		$this->view(
			'sessions',
			array(
				'rows'    => Ejabh_Sessions::all(),
				'summary' => Ejabh_Sessions::summary(),
			)
		);
	}

	/**
	 * File scan.
	 *
	 * @return void
	 */
	public function render_files() {
		$this->view(
			'scan',
			array(
				'kind'     => 'file',
				'title'    => __( 'فحص ملفات الاستضافة', 'ejabh-security' ),
				'intro'    => __( 'يفحص كل ملف على الاستضافة: يقارن ملفات نواة ووردبريس ببصماتها الرسمية، يبحث عن أنماط الأبواب الخلفية والتعمية، ويكشف ملفات PHP في أماكن لا يجوز أن توجد فيها.', 'ejabh-security' ),
				'state'    => Ejabh_File_Scanner::state(),
				'findings' => Ejabh_Findings::get( 'file', 800 ),
				'counts'   => Ejabh_Findings::counts( 'file' ),
				'back'     => self::MENU . '-files',
			)
		);
	}

	/**
	 * Database scan.
	 *
	 * @return void
	 */
	public function render_database() {
		$this->view(
			'scan',
			array(
				'kind'     => 'db',
				'title'    => __( 'فحص قاعدة البيانات', 'ejabh-security' ),
				'intro'    => __( 'يفحص قاعدة البيانات بحثاً عن كود محقون في المحتوى والإعدادات، حسابات مدير مزروعة، مهام مجدولة مشبوهة، وإعدادات تحصين ناقصة.', 'ejabh-security' ),
				'state'    => Ejabh_DB_Scanner::state(),
				'findings' => Ejabh_Findings::get( 'db', 800 ),
				'counts'   => Ejabh_Findings::counts( 'db' ),
				'back'     => self::MENU . '-database',
			)
		);
	}

	/**
	 * Plugin/theme integrity audit.
	 *
	 * @return void
	 */
	public function render_integrity() {
		$this->view(
			'scan',
			array(
				'kind'     => 'integrity',
				'title'    => __( 'تدقيق نزاهة الإضافات والقوالب', 'ejabh-security' ),
				'intro'    => __( 'يقارن ملفات كل إضافة ببصماتها الرسمية المنشورة على wordpress.org. هذه الطريقة الوحيدة لكشف إضافة سليمة أُضيف إليها باب خلفي، أو ملف PHP دخيل مدسوس داخل مجلدها. الإضافات المدفوعة والقوالب لا بصمات لها، فتُدرَج كـ"غير قابلة للتحقق" بدل اعتبارها سليمة.', 'ejabh-security' ),
				'state'    => Ejabh_Integrity::state(),
				'findings' => Ejabh_Findings::get( 'integrity', 800 ),
				'counts'   => Ejabh_Findings::counts( 'integrity' ),
				'back'     => self::MENU . '-integrity',
			)
		);
	}

	/**
	 * Hardening checks and fixes.
	 *
	 * @return void
	 */
	public function render_hardening() {
		$key    = 'dys_sec_harden_result_' . get_current_user_id();
		$result = get_transient( $key );
		if ( $result ) {
			delete_transient( $key );
		}

		$this->view(
			'hardening',
			array(
				'checks' => Ejabh_Hardening::checks(),
				'result' => is_array( $result ) ? $result : null,
			)
		);
	}

	/**
	 * Quarantine and blocked IPs.
	 *
	 * @return void
	 */
	public function render_quarantine() {
		$key    = 'dys_sec_harden_result_' . get_current_user_id();
		$result = get_transient( $key );
		if ( $result ) {
			delete_transient( $key );
		}

		$this->view(
			'quarantine',
			array(
				'rows'   => Ejabh_Quarantine::all(),
				'blocks' => Ejabh_Login_Limiter::recent( 100 ),
				'result' => is_array( $result ) ? $result : null,
			)
		);
	}

	/**
	 * Event log.
	 *
	 * @return void
	 */
	public function render_log() {
		$severity = isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$this->view(
			'log',
			array(
				'rows'     => Ejabh_Logger::recent( 300, $severity ),
				'severity' => $severity,
			)
		);
	}

	/**
	 * Settings.
	 *
	 * @return void
	 */
	public function render_settings() {
		$uid = get_current_user_id();

		$invalid = get_transient( 'dys_sec_invalid_emails_' . $uid );
		$tested  = get_transient( 'dys_sec_test_report_' . $uid );
		delete_transient( 'dys_sec_invalid_emails_' . $uid );
		delete_transient( 'dys_sec_test_report_' . $uid );

		$this->view(
			'settings',
			array(
				'settings'       => Ejabh_Settings::all(),
				'admins'         => get_users( array( 'role' => 'administrator', 'orderby' => 'ID' ) ),
				'invalid_emails' => is_array( $invalid ) ? $invalid : array(),
				'test_result'    => is_array( $tested ) ? $tested : array(),
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * Shared view helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Coloured severity badge.
	 *
	 * @param string $severity Severity slug.
	 * @return string
	 */
	public function severity_badge( $severity ) {
		$labels = array(
			'critical' => __( 'حرج', 'ejabh-security' ),
			'high'     => __( 'عالي', 'ejabh-security' ),
			'medium'   => __( 'متوسط', 'ejabh-security' ),
			'low'      => __( 'منخفض', 'ejabh-security' ),
			'warning'  => __( 'تحذير', 'ejabh-security' ),
			'info'     => __( 'معلومة', 'ejabh-security' ),
		);
		$label = isset( $labels[ $severity ] ) ? $labels[ $severity ] : $severity;

		return sprintf(
			'<span class="ejabh-badge ejabh-badge--%s">%s</span>',
			esc_attr( $severity ),
			esc_html( $label )
		);
	}

	/**
	 * Relative time string.
	 *
	 * @param int|string $when Timestamp or MySQL datetime (UTC).
	 * @return string
	 */
	public function ago( $when ) {
		$ts = is_numeric( $when ) ? (int) $when : strtotime( (string) $when . ' UTC' );
		if ( ! $ts ) {
			return '—';
		}
		if ( $ts > time() ) {
			return sprintf(
				/* translators: %s: human readable time difference. */
				__( 'بعد %s', 'ejabh-security' ),
				human_time_diff( time(), $ts )
			);
		}
		return sprintf(
			/* translators: %s: human readable time difference. */
			__( 'قبل %s', 'ejabh-security' ),
			human_time_diff( $ts, time() )
		);
	}
}
