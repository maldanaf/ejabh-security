<?php
/**
 * Plugin bootstrap and shared AJAX endpoints.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Wires every component together.
 */
class Ejabh_Plugin {

	const DAILY_HOOK = 'dys_sec_daily';

	/**
	 * Two-factor component.
	 *
	 * @var Ejabh_2FA
	 */
	public $twofa;

	/**
	 * Sessions component.
	 *
	 * @var Ejabh_Sessions
	 */
	public $sessions;

	/**
	 * Plugin guard component.
	 *
	 * @var Ejabh_Plugin_Guard
	 */
	public $guard;

	/**
	 * Capability lockdown component.
	 *
	 * @var Ejabh_Caps
	 */
	public $caps;

	/**
	 * Account protection component.
	 *
	 * @var Ejabh_User_Guard
	 */
	public $users;

	/**
	 * Login throttling component.
	 *
	 * @var Ejabh_Login_Limiter
	 */
	public $limiter;

	/**
	 * Hardening component.
	 *
	 * @var Ejabh_Hardening
	 */
	public $hardening;

	/**
	 * Scheduler component.
	 *
	 * @var Ejabh_Scheduler
	 */
	public $scheduler;

	/**
	 * Report component.
	 *
	 * @var Ejabh_Report
	 */
	public $report;

	/**
	 * New-file watcher component.
	 *
	 * @var Ejabh_Watcher
	 */
	public $watcher;

	/**
	 * Daily report component.
	 *
	 * @var Ejabh_Daily_Report
	 */
	public $daily_report;

	/**
	 * GitHub updater component.
	 *
	 * @var Ejabh_Updater
	 */
	public $updater;

	/**
	 * Admin notice cleanup component.
	 *
	 * @var Ejabh_Clean_Admin
	 */
	public $clean_admin;

	/**
	 * Admin UI component.
	 *
	 * @var Ejabh_Admin|null
	 */
	public $admin = null;

	/**
	 * Register everything.
	 *
	 * @return void
	 */
	public function boot() {
		$this->twofa     = new Ejabh_2FA();
		$this->sessions  = new Ejabh_Sessions();
		$this->guard     = new Ejabh_Plugin_Guard();
		$this->caps      = new Ejabh_Caps();
		$this->users     = new Ejabh_User_Guard();
		$this->limiter   = new Ejabh_Login_Limiter();
		$this->hardening = new Ejabh_Hardening();
		$this->scheduler = new Ejabh_Scheduler();
		$this->report    = new Ejabh_Report();
		$this->watcher      = new Ejabh_Watcher();
		$this->daily_report = new Ejabh_Daily_Report();
		$this->updater      = new Ejabh_Updater();
		$this->clean_admin  = new Ejabh_Clean_Admin();

		// Since WordPress 6.7 translations must not load before `init`.
		add_action( 'init', array( $this, 'load_textdomain' ) );

		$this->twofa->hooks();
		$this->sessions->hooks();
		$this->guard->hooks();
		$this->caps->hooks();
		$this->users->hooks();
		$this->limiter->hooks();
		$this->hardening->hooks();
		$this->scheduler->hooks();
		$this->report->hooks();
		$this->watcher->hooks();
		$this->daily_report->hooks();
		$this->updater->hooks();

		if ( is_admin() ) {
			$this->clean_admin->hooks();
		}

		add_action( 'admin_post_dys_sec_quarantine', array( $this, 'handle_quarantine' ) );

		add_action( self::DAILY_HOOK, array( $this, 'daily_maintenance' ) );
		add_action( 'admin_init', array( $this, 'maybe_upgrade' ), 5 );
		add_action( 'admin_init', array( $this, 'retire_legacy_plugin' ), 6 );
		add_action( 'admin_init', array( __CLASS__, 'ensure_schedules' ), 20 );

		// Surface the reason a login attempt was interrupted.
		add_filter( 'login_message', array( $this, 'login_messages' ) );

		// Scanner endpoints.
		add_action( 'wp_ajax_dys_sec_scan', array( $this, 'ajax_scan' ) );

		if ( is_admin() && class_exists( 'Ejabh_Admin' ) ) {
			$this->admin = new Ejabh_Admin( $this );
			$this->admin->hooks();
		}
	}

	/**
	 * Load translations.
	 *
	 * @return void
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'ejabh-security', false, dirname( EJABH_SEC_BASENAME ) . '/languages' );
	}

	/**
	 * Notices shown on wp-login.php.
	 *
	 * @param string $message Existing message markup.
	 * @return string
	 */
	public function login_messages( $message ) {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['dys_expired'] ) ) {
			$message .= '<p class="message">' . esc_html__( 'انتهت مدة التحقق. سجّل الدخول من جديد.', 'ejabh-security' ) . '</p>';
		}
		if ( ! empty( $_GET['dys_locked'] ) ) {
			$message .= '<div id="login_error">' . esc_html__( 'أُلغيت محاولة الدخول بسبب إدخال رمز تحقق خاطئ عدة مرات. سجّل الدخول من جديد.', 'ejabh-security' ) . '</div>';
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		return $message;
	}

	/**
	 * Quarantine actions from the findings and quarantine screens.
	 *
	 * @return void
	 */
	public function handle_quarantine() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_quarantine' );

		$what = isset( $_POST['what'] ) ? sanitize_key( wp_unslash( $_POST['what'] ) ) : '';
		$back = isset( $_POST['back'] ) ? sanitize_key( wp_unslash( $_POST['back'] ) ) : 'ejabh-security-quarantine';

		switch ( $what ) {
			case 'capture':
				$target = isset( $_POST['target'] ) ? wp_unslash( $_POST['target'] ) : '';
				// Only site-relative paths, never absolute or traversing.
				$target = ltrim( str_replace( array( '..', '\\' ), array( '', '/' ), (string) $target ), '/' );
				$result = $target
					? Ejabh_Quarantine::capture( ABSPATH . $target, __( 'حجر يدوي من نتائج الفحص', 'ejabh-security' ) )
					: array(
						'ok'  => false,
						'msg' => __( 'مسار غير صالح.', 'ejabh-security' ),
					);
				break;

			case 'restore':
				$result = Ejabh_Quarantine::restore( isset( $_POST['id'] ) ? (int) $_POST['id'] : 0 );
				break;

			case 'purge':
				$result = Ejabh_Quarantine::purge( isset( $_POST['id'] ) ? (int) $_POST['id'] : 0 );
				break;

			default:
				$result = array(
					'ok'  => false,
					'msg' => __( 'إجراء غير معروف.', 'ejabh-security' ),
				);
		}

		set_transient( 'dys_sec_harden_result_' . get_current_user_id(), $result, 60 );
		wp_safe_redirect( admin_url( 'admin.php?page=' . $back ) );
		exit;
	}

	/**
	 * Create or update the plugin tables when the version changes.
	 *
	 * Covers the case where the plugin files were copied into place without the
	 * activation hook ever running, which would otherwise leave logging and
	 * scan results silently writing to tables that do not exist.
	 *
	 * @return void
	 */
	public function maybe_upgrade() {
		if ( get_option( 'dys_sec_db_version' ) === EJABH_SEC_VERSION ) {
			return;
		}

		self::install_tables();
		self::migrate_settings();
		Ejabh_Plugin_Guard::schedule();
		Ejabh_Scheduler::reschedule();
		Ejabh_Watcher::reschedule();
		Ejabh_Daily_Report::reschedule();
		self::ensure_schedules();

		update_option( 'dys_sec_db_version', EJABH_SEC_VERSION, false );
	}

	/**
	 * Carry pre-2.0 settings forward.
	 *
	 * @return void
	 */
	private static function migrate_settings() {
		$stored = get_option( Ejabh_Settings::OPTION, array() );
		if ( ! is_array( $stored ) ) {
			return;
		}

		// The single alert address becomes the first entry of the list.
		if ( empty( $stored['notify_emails'] ) && ! empty( $stored['notify_email'] ) && is_email( $stored['notify_email'] ) ) {
			Ejabh_Settings::update( array( 'notify_emails' => array( strtolower( (string) $stored['notify_email'] ) ) ) );
		}
	}

	/**
	 * Re-create any missing recurring job.
	 *
	 * The pre-rename plugin used the same cron hook names, so deactivating it
	 * after this one is active unschedules our jobs too. Checking costs one
	 * read of the already-loaded cron option.
	 *
	 * @return void
	 */
	public static function ensure_schedules() {
		if ( ! wp_next_scheduled( self::DAILY_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::DAILY_HOOK );
		}
		if ( Ejabh_Settings::get( 'sched_scan_enabled' ) && ! wp_next_scheduled( Ejabh_Scheduler::HOOK ) ) {
			Ejabh_Scheduler::reschedule();
		}
		if ( Ejabh_Settings::get( 'watch_enabled' ) && ! wp_next_scheduled( Ejabh_Watcher::HOOK ) ) {
			Ejabh_Watcher::reschedule();
		}
		if ( Ejabh_Settings::get( 'report_daily_enabled' ) && ! wp_next_scheduled( Ejabh_Daily_Report::HOOK ) ) {
			Ejabh_Daily_Report::reschedule();
		}
		Ejabh_Plugin_Guard::schedule();
	}

	/**
	 * Deactivate the pre-rename "DYS Security" plugin if it is still active.
	 *
	 * Running both would challenge every login for two codes and double every
	 * alert. Deactivation is silent so its deactivation hook — which would
	 * unschedule the cron jobs both versions share — does not run.
	 *
	 * @return void
	 */
	public function retire_legacy_plugin() {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( ! is_plugin_active( EJABH_SEC_LEGACY_BASENAME ) ) {
			return;
		}

		deactivate_plugins( EJABH_SEC_LEGACY_BASENAME, true );
		Ejabh_Logger::log( 'legacy_plugin_retired', 'عُطّلت إضافة DYS Security القديمة تلقائياً بعد تفعيل Ejabh Security (الإعدادات والبيانات انتقلت كما هي). يمكن حذف مجلد dys-security الآن.', 'warning' );
	}

	/**
	 * Create every table the plugin owns.
	 *
	 * @return void
	 */
	private static function install_tables() {
		Ejabh_Logger::install();
		Ejabh_Findings::install();
		Ejabh_FIM::install();
		Ejabh_Login_Limiter::install();
		Ejabh_Quarantine::install();
	}

	/**
	 * Daily housekeeping.
	 *
	 * @return void
	 */
	public function daily_maintenance() {
		Ejabh_Logger::prune( 90 );
		Ejabh_Login_Limiter::prune();
		$this->guard->sweep();
	}

	/* ---------------------------------------------------------------------
	 * AJAX
	 * ------------------------------------------------------------------ */

	/**
	 * Drive the file and database scanners from the admin screens.
	 *
	 * @return void
	 */
	public function ajax_scan() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'ليست لديك صلاحية.', 'ejabh-security' ) ), 403 );
		}
		check_ajax_referer( 'dys_sec_scan' );

		$kind = isset( $_POST['kind'] ) ? sanitize_key( wp_unslash( $_POST['kind'] ) ) : '';
		$op   = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : 'step';

		$classes = array(
			'file'      => 'Ejabh_File_Scanner',
			'db'        => 'Ejabh_DB_Scanner',
			'integrity' => 'Ejabh_Integrity',
		);

		if ( ! isset( $classes[ $kind ] ) ) {
			wp_send_json_error( array( 'message' => __( 'نوع فحص غير معروف.', 'ejabh-security' ) ), 400 );
		}

		$class = $classes[ $kind ];

		switch ( $op ) {
			case 'start':
				$state = $class::start();
				break;
			case 'cancel':
				$class::cancel();
				$state = $class::state();
				break;
			case 'step':
			default:
				$state = $class::step();
				break;
		}

		wp_send_json_success( $this->scan_payload( $kind, $state ) );
	}

	/**
	 * Shape the scan state for the browser.
	 *
	 * @param string $kind  file|db.
	 * @param array  $state Scanner state.
	 * @return array
	 */
	private function scan_payload( $kind, array $state ) {
		$counts = Ejabh_Findings::counts( $kind );

		$payload = array(
			'status'  => $state['status'],
			'counts'  => $counts,
			'total'   => array_sum( $counts ),
			'done'    => 'done' === $state['status'],
			'running' => 'scanning' === $state['status'],
		);

		if ( 'file' === $kind ) {
			$payload['progress'] = sprintf(
				/* translators: 1: files scanned, 2: directories done, 3: directories queued. */
				__( 'تم فحص %1$s ملف في %2$s مجلد — %3$s مجلد في الانتظار', 'ejabh-security' ),
				number_format_i18n( $state['scanned'] ),
				number_format_i18n( $state['dirs_done'] ),
				number_format_i18n( count( (array) $state['stack'] ) )
			);
			$payload['core'] = $state['core_stats'];
		} elseif ( 'integrity' === $kind ) {
			$payload['progress'] = sprintf(
				/* translators: 1: checked, 2: remaining. */
				__( 'تم تدقيق %1$s إضافة/قالب — %2$s متبقٍ', 'ejabh-security' ),
				number_format_i18n( $state['checked'] ),
				number_format_i18n( count( (array) $state['queue'] ) )
			);
		} else {
			$payload['progress'] = sprintf(
				/* translators: 1: task label, 2: rows examined. */
				__( 'المرحلة: %1$s — تم فحص %2$s صف', 'ejabh-security' ),
				Ejabh_DB_Scanner::task_label( (int) $state['task'] ),
				number_format_i18n( $state['rows'] )
			);
		}

		if ( $payload['done'] ) {
			$payload['progress'] = sprintf(
				/* translators: %s: number of findings. */
				__( 'اكتمل الفحص — %s نتيجة.', 'ejabh-security' ),
				number_format_i18n( $payload['total'] )
			);
		}

		return $payload;
	}

	/* ---------------------------------------------------------------------
	 * Lifecycle
	 * ------------------------------------------------------------------ */

	/**
	 * Activation: create tables, seed settings, schedule jobs.
	 *
	 * @return void
	 */
	public static function activate() {
		self::install_tables();

		$settings = get_option( Ejabh_Settings::OPTION, array() );
		if ( ! is_array( $settings ) ) {
			$settings = array();
		}

		// Seed the owner with whoever activated the plugin, falling back to the
		// lowest-ID administrator.
		if ( empty( $settings['caps_owner_id'] ) ) {
			$current = get_current_user_id();
			if ( $current && user_can( $current, 'manage_options' ) ) {
				$settings['caps_owner_id'] = (int) $current;
			} else {
				$settings['caps_owner_id'] = Ejabh_Settings::first_admin_id();
			}
		}

		if ( empty( $settings['notify_email'] ) ) {
			$settings['notify_email'] = (string) get_option( 'admin_email' );
		}

		if ( empty( $settings['notify_emails'] ) ) {
			$settings['notify_emails'] = array( strtolower( (string) $settings['notify_email'] ) );
		}

		update_option( Ejabh_Settings::OPTION, array_merge( Ejabh_Settings::defaults(), $settings ), false );
		update_option( 'dys_sec_db_version', EJABH_SEC_VERSION, false );

		// Hand over from the pre-rename plugin before scheduling, so nothing it
		// does on the way out can touch the jobs created below.
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( is_plugin_active( EJABH_SEC_LEGACY_BASENAME ) ) {
			deactivate_plugins( EJABH_SEC_LEGACY_BASENAME, true );
		}

		Ejabh_Plugin_Guard::schedule();
		Ejabh_Scheduler::reschedule();
		Ejabh_Watcher::reschedule();
		Ejabh_Daily_Report::reschedule();
		self::ensure_schedules();

		// Adopt the current administrator set as the approved baseline, so the
		// reconciler only reports accounts that appear from now on.
		$guard = new Ejabh_User_Guard();
		$guard->remember_admins();

		Ejabh_Logger::log( 'plugin_activated', 'تم تفعيل إضافة Ejabh Security.', 'info' );
	}

	/**
	 * Deactivation: stop scheduled jobs. Data is intentionally preserved.
	 *
	 * @return void
	 */
	public static function deactivate() {
		Ejabh_Plugin_Guard::unschedule();
		Ejabh_Scheduler::unschedule();
		Ejabh_Watcher::unschedule();
		Ejabh_Daily_Report::unschedule();

		$timestamp = wp_next_scheduled( self::DAILY_HOOK );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, self::DAILY_HOOK );
		}

		delete_transient( 'dys_sec_guard_swept' );

		Ejabh_Logger::log( 'plugin_deactivated', 'تم تعطيل إضافة Ejabh Security.', 'warning' );
	}
}
