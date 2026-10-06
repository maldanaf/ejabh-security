<?php
/**
 * Outgoing mail.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Builds and sends the plugin's transactional mail.
 */
class Ejabh_Mailer {

	/** Critical-event e-mails allowed per hour before they wait for the daily report. */
	const ALERTS_PER_HOUR = 15;

	const ALERT_COUNTER = 'dys_sec_alerts_sent';

	/**
	 * Send a one-time login code.
	 *
	 * @param WP_User $user User logging in.
	 * @param string  $code Plain-text code.
	 * @return bool True when wp_mail() accepted the message.
	 */
	public static function send_login_code( $user, $code ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$ttl  = (int) Ejabh_Settings::get( '2fa_code_ttl' );
		$mins = max( 1, (int) round( $ttl / 60 ) );

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] رمز تسجيل الدخول', 'ejabh-security' ), $site );

		$ip = Ejabh_Logger::client_ip();
		$ua = Ejabh_Logger::client_ua();

		$lines = array(
			sprintf( __( 'مرحباً %s،', 'ejabh-security' ), $user->display_name ),
			'',
			__( 'تم طلب تسجيل الدخول إلى حسابك. رمز التحقق الخاص بك هو:', 'ejabh-security' ),
			'',
			'        ' . $code,
			'',
			sprintf( __( 'الرمز صالح لمدة %d دقيقة ولمرة واحدة فقط.', 'ejabh-security' ), $mins ),
			'',
			__( 'تفاصيل محاولة الدخول:', 'ejabh-security' ),
			sprintf( __( '• عنوان IP: %s', 'ejabh-security' ), $ip ? $ip : __( 'غير معروف', 'ejabh-security' ) ),
			sprintf( __( '• المتصفح: %s', 'ejabh-security' ), $ua ? $ua : __( 'غير معروف', 'ejabh-security' ) ),
			sprintf( __( '• الوقت: %s UTC', 'ejabh-security' ), current_time( 'Y-m-d H:i:s', true ) ),
			'',
			__( '⚠️ إذا لم تكن أنت من طلب هذا الرمز، فهذا يعني أن كلمة مرورك معروفة لشخص آخر.', 'ejabh-security' ),
			__( 'لا تشارك الرمز مع أي شخص، وقم بتغيير كلمة المرور فوراً وأبلغ مسؤول الموقع.', 'ejabh-security' ),
			'',
			'— ' . $site,
		);

		return self::send( $user->user_email, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Tell a user their account was locked after too many bad codes.
	 *
	 * @param WP_User $user User in question.
	 * @return void
	 */
	public static function send_lockout_notice( $user ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] تحذير أمني: محاولات دخول فاشلة', 'ejabh-security' ), $site );

		$lines = array(
			sprintf( __( 'مرحباً %s،', 'ejabh-security' ), $user->display_name ),
			'',
			__( 'تم إدخال رمز تحقق خاطئ عدة مرات على حسابك، وتم إلغاء محاولة الدخول.', 'ejabh-security' ),
			'',
			sprintf( __( '• عنوان IP: %s', 'ejabh-security' ), Ejabh_Logger::client_ip() ),
			sprintf( __( '• الوقت: %s UTC', 'ejabh-security' ), current_time( 'Y-m-d H:i:s', true ) ),
			'',
			__( 'إذا لم تكن أنت، فكلمة مرورك مسربة. غيّرها فوراً.', 'ejabh-security' ),
			'',
			'— ' . $site,
		);

		self::send( $user->user_email, $subject, implode( "\n", $lines ) );
	}

	/**
	 * Warn a user that their account was used from an unfamiliar address.
	 *
	 * @param WP_User $user The account.
	 * @param string  $ip   The new address.
	 * @return void
	 */
	public static function send_new_location_alert( $user, $ip ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] تنبيه: دخول من جهاز أو مكان جديد', 'ejabh-security' ), $site );

		$lines = array(
			sprintf( __( 'مرحباً %s،', 'ejabh-security' ), $user->display_name ),
			'',
			__( 'تم تسجيل الدخول إلى حسابك من عنوان لم يُستخدم من قبل:', 'ejabh-security' ),
			'',
			sprintf( __( '• عنوان IP: %s', 'ejabh-security' ), $ip ),
			sprintf( __( '• المتصفح: %s', 'ejabh-security' ), Ejabh_Logger::client_ua() ),
			sprintf( __( '• الوقت: %s UTC', 'ejabh-security' ), current_time( 'Y-m-d H:i:s', true ) ),
			'',
			__( 'إن كنت أنت، تجاهل هذه الرسالة.', 'ejabh-security' ),
			__( '⚠️ إن لم تكن أنت، فحسابك مخترق الآن: غيّر كلمة المرور فوراً وأبلغ مسؤول الموقع لإنهاء الجلسات النشطة.', 'ejabh-security' ),
			'',
			'— ' . $site,
		);

		self::send( $user->user_email, $subject, implode( "\n", $lines ) );

		// The security contact should know too when it is a privileged account.
		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			$admin_lines = array(
				sprintf(
					/* translators: 1: user login, 2: user id, 3: ip. */
					__( 'دخل حساب المدير %1$s (#%2$d) من عنوان جديد: %3$s', 'ejabh-security' ),
					$user->user_login,
					$user->ID,
					$ip
				),
				sprintf( __( 'الوقت: %s UTC', 'ejabh-security' ), current_time( 'Y-m-d H:i:s', true ) ),
				'',
				sprintf( __( 'راجع الجلسات النشطة: %s', 'ejabh-security' ), admin_url( 'admin.php?page=ejabh-security-sessions' ) ),
			);

			self::send_team( $subject, implode( "\n", $admin_lines ) );
		}
	}

	/**
	 * Mail the outcome of an unattended scheduled scan.
	 *
	 * @param array $counts       Current severity counts.
	 * @param int   $new_critical Newly appeared critical findings.
	 * @param int   $new_high     Newly appeared high findings.
	 * @return void
	 */
	public static function send_scan_summary( array $counts, $new_critical, $new_high, array $changes = array(), array $files = array() ) {
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		$changes = wp_parse_args(
			$changes,
			array(
				'new'     => 0,
				'changed' => 0,
				'gone'    => 0,
			)
		);

		// Lead with whichever signal is strongest, so the subject line alone
		// tells the reader whether to stop what they are doing.
		if ( $changes['new'] > 0 ) {
			/* translators: 1: site name, 2: number of new files. */
			$subject = sprintf( __( '[%1$s] ⚠️ ظهر %2$d ملف PHP جديد على الموقع', 'ejabh-security' ), $site, (int) $changes['new'] );
		} elseif ( $new_critical > 0 ) {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] 🔴 نتائج حرجة جديدة في الفحص التلقائي', 'ejabh-security' ), $site );
		} else {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] الفحص التلقائي: تغيّرات جديدة', 'ejabh-security' ), $site );
		}

		$lines = array(
			__( 'اكتمل الفحص الأمني المجدول، وهذا ما تغيّر منذ الفحص السابق:', 'ejabh-security' ),
			'',
			__( 'تغيّرات الملفات:', 'ejabh-security' ),
			sprintf( __( '• ملفات PHP جديدة: %d', 'ejabh-security' ), (int) $changes['new'] ),
			sprintf( __( '• ملفات PHP تعدّلت: %d', 'ejabh-security' ), (int) $changes['changed'] ),
			sprintf( __( '• ملفات PHP حُذفت: %d', 'ejabh-security' ), (int) $changes['gone'] ),
		);

		if ( $files ) {
			$lines[] = '';
			$lines[] = __( 'الملفات:', 'ejabh-security' );
			foreach ( $files as $file ) {
				$lines[] = '   ' . $file;
			}
		}

		$lines[] = '';
		$lines[] = __( 'نتائج الفحص:', 'ejabh-security' );
		$lines[] = sprintf( __( '• حرجة جديدة: %d · عالية جديدة: %d', 'ejabh-security' ), (int) $new_critical, (int) $new_high );
		$lines[] = sprintf( __( '• الإجمالي — حرج: %d · عالي: %d · متوسط: %d · منخفض: %d', 'ejabh-security' ), (int) $counts['critical'], (int) $counts['high'], (int) $counts['medium'], (int) $counts['low'] );
		$lines[] = '';

		if ( $changes['new'] > 0 ) {
			$lines[] = __( '⚠️ ظهور ملف PHP جديد دون أن تُجروا تحديثاً هو أوضح مؤشر على اختراق. افتح الملفات أعلاه فوراً.', 'ejabh-security' );
			$lines[] = '';
		}

		$lines[] = sprintf( __( 'راجع التفاصيل: %s', 'ejabh-security' ), admin_url( 'admin.php?page=ejabh-security-files' ) );
		$lines[] = '';
		$lines[] = '— ' . $site;

		self::send_team( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Alert the security contact about a critical event.
	 *
	 * @param string $event   Event slug.
	 * @param string $message Detail.
	 * @return void
	 */
	public static function notify_critical( $event, $message ) {
		// An attack can produce dozens of critical events in minutes. Past the
		// hourly cap the events are still logged and appear in the daily report,
		// but nobody's inbox is flooded into ignoring the plugin.
		// Fixed window: re-setting a transient would push its expiry forward
		// on every alert and the cap would never lift during a long attack.
		$window = get_option( self::ALERT_COUNTER, array() );
		if ( ! is_array( $window ) || empty( $window['start'] ) || time() - (int) $window['start'] >= HOUR_IN_SECONDS ) {
			$window = array(
				'start' => time(),
				'count' => 0,
			);
		}
		if ( (int) $window['count'] >= self::ALERTS_PER_HOUR ) {
			return;
		}
		++$window['count'];
		update_option( self::ALERT_COUNTER, $window, false );

		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		/* translators: %s: site name. */
		$subject = sprintf( __( '[%s] 🔴 حدث أمني حرج', 'ejabh-security' ), $site );

		$lines = array(
			__( 'سجّلت إضافة الحماية حدثاً حرجاً على الموقع:', 'ejabh-security' ),
			'',
			sprintf( __( '• النوع: %s', 'ejabh-security' ), $event ),
			sprintf( __( '• التفاصيل: %s', 'ejabh-security' ), $message ),
			sprintf( __( '• عنوان IP: %s', 'ejabh-security' ), Ejabh_Logger::client_ip() ),
			sprintf( __( '• الوقت: %s UTC', 'ejabh-security' ), current_time( 'Y-m-d H:i:s', true ) ),
			'',
			sprintf( __( 'راجع السجل الكامل: %s', 'ejabh-security' ), admin_url( 'admin.php?page=ejabh-security-log' ) ),
			'',
			'— ' . $site,
		);

		self::send_team( $subject, implode( "\n", $lines ) );
	}

	/**
	 * Send to every configured security recipient.
	 *
	 * One message per address rather than one message with everyone in To:
	 * recipients do not see each other's addresses, and a single rejected
	 * address cannot stop the others receiving it.
	 *
	 * @param string $subject Subject.
	 * @param string $body    Plain-text body.
	 * @param string $html    Optional HTML body; sent instead of $body when given.
	 * @return array Address => bool accepted by wp_mail().
	 */
	public static function send_team( $subject, $body, $html = '' ) {
		$results = array();
		foreach ( Ejabh_Settings::notify_recipients() as $to ) {
			$results[ $to ] = $html ? self::send_html( $to, $subject, $html, $body ) : self::send( $to, $subject, $body );
		}
		return $results;
	}

	/**
	 * Send an HTML message with a plain-text alternative.
	 *
	 * @param string $to      Recipient.
	 * @param string $subject Subject.
	 * @param string $html    HTML body.
	 * @param string $text    Plain-text alternative.
	 * @return bool
	 */
	private static function send_html( $to, $subject, $html, $text ) {
		if ( ! $to || ! is_email( $to ) ) {
			return false;
		}

		$type = static function () {
			return 'text/html';
		};
		$alt = static function ( $phpmailer ) use ( $text ) {
			$phpmailer->AltBody = $text; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
		};

		add_filter( 'wp_mail_content_type', $type );
		add_action( 'phpmailer_init', $alt );
		$sent = wp_mail( $to, $subject, $html );
		remove_action( 'phpmailer_init', $alt );
		remove_filter( 'wp_mail_content_type', $type );

		return (bool) $sent;
	}

	/**
	 * Low-level send with a plain-text content type.
	 *
	 * @param string $to      Recipient.
	 * @param string $subject Subject.
	 * @param string $body    Message body.
	 * @return bool
	 */
	private static function send( $to, $subject, $body ) {
		if ( ! $to || ! is_email( $to ) ) {
			return false;
		}

		$plain = static function () {
			return 'text/plain';
		};

		add_filter( 'wp_mail_content_type', $plain );
		$sent = wp_mail( $to, $subject, $body );
		remove_filter( 'wp_mail_content_type', $plain );

		return (bool) $sent;
	}
}
