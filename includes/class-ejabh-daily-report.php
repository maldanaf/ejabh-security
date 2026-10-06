<?php
/**
 * Daily security report.
 *
 * One e-mail a day to every security recipient: what is open, what happened in
 * the last 24 hours, and what is still unhardened. Urgent events are mailed the
 * moment they happen; this report is the steady heartbeat that proves the
 * plugin is alive, and that a silent inbox means a quiet day rather than a
 * broken mailer.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Builds and schedules the daily digest.
 */
class Ejabh_Daily_Report {

	const HOOK = 'dys_sec_daily_report';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( self::HOOK, array( $this, 'send' ) );
	}

	/**
	 * (Re)schedule for the configured local hour.
	 *
	 * @return void
	 */
	public static function reschedule() {
		self::unschedule();

		if ( ! Ejabh_Settings::get( 'report_daily_enabled' ) ) {
			return;
		}

		wp_schedule_event( self::next_run(), 'daily', self::HOOK );
	}

	/**
	 * Remove the schedule.
	 *
	 * @return void
	 */
	public static function unschedule() {
		$next = wp_next_scheduled( self::HOOK );
		while ( $next ) {
			wp_unschedule_event( $next, self::HOOK );
			$next = wp_next_scheduled( self::HOOK );
		}
	}

	/**
	 * Next occurrence of the configured hour, in the site's timezone.
	 *
	 * @return int Unix timestamp.
	 */
	public static function next_run() {
		$hour = max( 0, min( 23, (int) Ejabh_Settings::get( 'report_daily_hour' ) ) );
		$tz   = wp_timezone();
		$now  = new DateTimeImmutable( 'now', $tz );
		$at   = $now->setTime( $hour, 0 );

		if ( $at <= $now ) {
			$at = $at->modify( '+1 day' );
		}

		return $at->getTimestamp();
	}

	/**
	 * Cron callback.
	 *
	 * @return array Address => accepted.
	 */
	public function send() {
		if ( ! Ejabh_Settings::get( 'report_daily_enabled' ) ) {
			return array();
		}
		return self::deliver();
	}

	/**
	 * Build and send now, regardless of the schedule.
	 *
	 * @param bool $test Mark the subject as a test.
	 * @return array Address => accepted by wp_mail().
	 */
	public static function deliver( $test = false ) {
		$data = self::collect();
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );

		if ( $data['critical_24h'] > 0 ) {
			/* translators: 1: site name, 2: count. */
			$subject = sprintf( __( '[%1$s] تقرير الأمان اليومي — ⚠️ %2$d حدث حرج خلال 24 ساعة', 'ejabh-security' ), $site, $data['critical_24h'] );
		} elseif ( $data['counts']['critical'] > 0 ) {
			/* translators: 1: site name, 2: count. */
			$subject = sprintf( __( '[%1$s] تقرير الأمان اليومي — 🔴 %2$d نتيجة حرجة ما زالت مفتوحة', 'ejabh-security' ), $site, $data['counts']['critical'] );
		} else {
			/* translators: %s: site name. */
			$subject = sprintf( __( '[%s] تقرير الأمان اليومي — ✅ لا جديد مقلق', 'ejabh-security' ), $site );
		}

		if ( $test ) {
			$subject = __( '[تجربة] ', 'ejabh-security' ) . $subject;
		}

		$results = Ejabh_Mailer::send_team( $subject, self::render_text( $data ), self::render_html( $data ) );

		Ejabh_Logger::log(
			$test ? 'daily_report_test' : 'daily_report_sent',
			sprintf(
				'أُرسل تقرير الأمان اليومي إلى %d مستلم (%d قُبل من خادم البريد).',
				count( $results ),
				count( array_filter( $results ) )
			),
			'info'
		);

		return $results;
	}

	/**
	 * Everything the report shows.
	 *
	 * @return array
	 */
	public static function collect() {
		global $wpdb;

		$since = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$table = Ejabh_Logger::table();

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$by_event = $wpdb->get_results(
			$wpdb->prepare( "SELECT event, COUNT(*) AS n FROM {$table} WHERE created_at >= %s GROUP BY event", $since ),
			OBJECT_K
		);
		$critical = $wpdb->get_results(
			$wpdb->prepare( "SELECT created_at, event, ip, message FROM {$table} WHERE created_at >= %s AND severity = 'critical' ORDER BY id DESC LIMIT 15", $since )
		);
		$critical_total = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE created_at >= %s AND severity = 'critical'", $since )
		);
		// phpcs:enable

		$n = static function ( $events ) use ( $by_event ) {
			$total = 0;
			foreach ( (array) $events as $event ) {
				$total += isset( $by_event[ $event ] ) ? (int) $by_event[ $event ]->n : 0;
			}
			return $total;
		};

		$failed_checks = array();
		foreach ( Ejabh_Hardening::checks() as $check ) {
			if ( 'fail' === $check['status'] ) {
				$failed_checks[] = $check['label'];
			}
		}

		$file_state = Ejabh_File_Scanner::state();
		$watch      = Ejabh_Watcher::state();

		return array(
			'counts'        => Ejabh_Findings::counts(),
			'critical_24h'  => $critical_total,
			'critical_rows' => (array) $critical,
			'activity'      => array(
				array( __( 'تسجيلات دخول ناجحة (بعد رمز التحقق)', 'ejabh-security' ), $n( '2fa_success' ), false ),
				array( __( 'دخول من عنوان جديد', 'ejabh-security' ), $n( 'login_new_ip' ), true ),
				array( __( 'محاولات دخول فاشلة', 'ejabh-security' ), $n( 'login_failed' ), false ),
				array( __( 'عناوين IP حُظرت', 'ejabh-security' ), $n( 'login_ip_blocked' ), false ),
				array( __( 'رموز تحقق خاطئة / إلغاء دخول', 'ejabh-security' ), $n( array( '2fa_bad_code', '2fa_lockout' ) ), true ),
				array( __( 'ملفات خبيثة اعتُرضت لحظة رفعها', 'ejabh-security' ), $n( 'upload_blocked' ), true ),
				array( __( 'ملفات خبيثة ظهرت على السيرفر وعُزلت', 'ejabh-security' ), $n( array( 'watch_neutralised', 'watch_detected' ) ), true ),
				array( __( 'ملفات نُقلت إلى الحجر', 'ejabh-security' ), $n( 'file_quarantined' ), true ),
				array( __( 'محاولات منح صلاحية مدير مُنعت', 'ejabh-security' ), $n( array( 'admin_promotion_blocked', 'unexpected_admin_detected' ) ), true ),
				array( __( 'إضافات محظورة مُنعت', 'ejabh-security' ), $n( array( 'guard_blocked_install', 'guard_blocked_activation', 'guard_blocked_load', 'guard_deleted' ) ), true ),
				array( __( 'تعديلات على wp-config.php', 'ejabh-security' ), $n( 'wpconfig_modified' ), true ),
				array( __( 'تغييرات في إعدادات الحماية', 'ejabh-security' ), $n( 'settings_saved' ), true ),
			),
			'failed_checks' => $failed_checks,
			'last_scan'     => ! empty( $file_state['finished'] ) ? (int) $file_state['finished'] : 0,
			'watch_last'    => (int) $watch['last_pass'],
			'watch_held'    => ! empty( $watch['held'] ),
			'watch_on'      => (bool) Ejabh_Settings::get( 'watch_enabled' ),
			'blocked_ips'   => Ejabh_Login_Limiter::active_block_count(),
			'dashboard'     => admin_url( 'admin.php?page=ejabh-security' ),
			'generated'     => wp_date( 'Y-m-d H:i' ),
		);
	}

	/**
	 * Human date for a timestamp, or a dash.
	 *
	 * @param int $ts Timestamp.
	 * @return string
	 */
	private static function when( $ts ) {
		return $ts ? wp_date( 'Y-m-d H:i', $ts ) : __( 'لم يحدث بعد', 'ejabh-security' );
	}

	/**
	 * Plain-text version.
	 *
	 * @param array $d Collected data.
	 * @return string
	 */
	public static function render_text( array $d ) {
		$c     = $d['counts'];
		$lines = array(
			sprintf( __( 'تقرير الأمان اليومي — %s', 'ejabh-security' ), $d['generated'] ),
			'',
			__( 'النتائج المفتوحة:', 'ejabh-security' ),
			sprintf( __( '• حرج: %1$d · عالي: %2$d · متوسط: %3$d · منخفض: %4$d', 'ejabh-security' ), $c['critical'], $c['high'], $c['medium'], $c['low'] ),
			'',
			__( 'آخر 24 ساعة:', 'ejabh-security' ),
		);

		foreach ( $d['activity'] as $row ) {
			$lines[] = sprintf( '• %s: %d', $row[0], $row[1] );
		}

		if ( $d['critical_rows'] ) {
			$lines[] = '';
			$lines[] = __( 'الأحداث الحرجة:', 'ejabh-security' );
			foreach ( $d['critical_rows'] as $row ) {
				$lines[] = sprintf( '• [%s UTC] %s', $row->created_at, wp_strip_all_tags( (string) $row->message ) );
			}
		}

		$lines[] = '';
		$lines[] = sprintf( __( 'آخر فحص ملفات كامل: %s', 'ejabh-security' ), self::when( $d['last_scan'] ) );
		$lines[] = $d['watch_on']
			? sprintf( __( 'مراقب الملفات الجديدة: آخر دورة %s', 'ejabh-security' ), self::when( $d['watch_last'] ) )
			: __( 'مراقب الملفات الجديدة: معطّل', 'ejabh-security' );

		if ( $d['failed_checks'] ) {
			$lines[] = '';
			$lines[] = __( 'بنود تحصين تحتاج إصلاحاً:', 'ejabh-security' );
			foreach ( $d['failed_checks'] as $label ) {
				$lines[] = '• ' . $label;
			}
		}

		$lines[] = '';
		$lines[] = sprintf( __( 'لوحة الحماية: %s', 'ejabh-security' ), $d['dashboard'] );

		return implode( "\n", $lines );
	}

	/**
	 * HTML version (inline styles only — mail clients strip <style>).
	 *
	 * @param array $d Collected data.
	 * @return string
	 */
	public static function render_html( array $d ) {
		$c    = $d['counts'];
		$site = esc_html( wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );

		$tile = static function ( $label, $value, $bg, $fg ) {
			return '<td style="padding:4px;"><div style="background:' . $bg . ';color:' . $fg . ';border-radius:8px;padding:12px 6px;text-align:center;">'
				. '<div style="font-size:24px;font-weight:700;line-height:1.1;">' . (int) $value . '</div>'
				. '<div style="font-size:12px;margin-top:4px;">' . esc_html( $label ) . '</div></div></td>';
		};

		$h  = '<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;background:#f3f4f6;padding:24px 12px;">';
		$h .= '<div style="max-width:620px;margin:0 auto;background:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #e5e7eb;">';
		$h .= '<div style="background:#111827;color:#ffffff;padding:18px 22px;">';
		$h .= '<div style="font-size:18px;font-weight:700;">' . esc_html__( 'تقرير الأمان اليومي', 'ejabh-security' ) . '</div>';
		$h .= '<div style="font-size:13px;opacity:.8;margin-top:4px;">' . $site . ' · ' . esc_html( $d['generated'] ) . '</div></div>';

		$h .= '<div style="padding:18px 18px 6px;"><div style="font-weight:700;color:#111827;margin:0 4px 8px;">' . esc_html__( 'النتائج المفتوحة', 'ejabh-security' ) . '</div>';
		$h .= '<table role="presentation" width="100%" style="border-collapse:collapse;"><tr>';
		$h .= $tile( __( 'حرج', 'ejabh-security' ), $c['critical'], $c['critical'] ? '#fee2e2' : '#f3f4f6', $c['critical'] ? '#991b1b' : '#374151' );
		$h .= $tile( __( 'عالي', 'ejabh-security' ), $c['high'], $c['high'] ? '#ffedd5' : '#f3f4f6', $c['high'] ? '#9a3412' : '#374151' );
		$h .= $tile( __( 'متوسط', 'ejabh-security' ), $c['medium'], '#f3f4f6', '#374151' );
		$h .= $tile( __( 'منخفض', 'ejabh-security' ), $c['low'], '#f3f4f6', '#374151' );
		$h .= '</tr></table></div>';

		$h .= '<div style="padding:12px 22px;"><div style="font-weight:700;color:#111827;margin-bottom:8px;">' . esc_html__( 'آخر 24 ساعة', 'ejabh-security' ) . '</div>';
		$h .= '<table role="presentation" width="100%" style="border-collapse:collapse;font-size:14px;">';
		foreach ( $d['activity'] as $row ) {
			$alarm = $row[2] && $row[1] > 0;
			$h    .= '<tr><td style="padding:7px 0;border-bottom:1px solid #f3f4f6;color:#374151;">' . esc_html( $row[0] ) . '</td>'
				. '<td style="padding:7px 0;border-bottom:1px solid #f3f4f6;text-align:left;font-weight:700;color:' . ( $alarm ? '#b91c1c' : '#111827' ) . ';">' . (int) $row[1] . '</td></tr>';
		}
		$h .= '</table></div>';

		if ( $d['critical_rows'] ) {
			$h .= '<div style="padding:12px 22px;"><div style="font-weight:700;color:#991b1b;margin-bottom:8px;">' . esc_html__( 'الأحداث الحرجة', 'ejabh-security' ) . '</div>';
			foreach ( $d['critical_rows'] as $row ) {
				$h .= '<div style="background:#fef2f2;border-right:3px solid #dc2626;padding:8px 10px;margin-bottom:6px;font-size:13px;color:#1f2937;">'
					. '<div style="color:#6b7280;font-size:11px;direction:ltr;text-align:right;">' . esc_html( $row->created_at ) . ' UTC · ' . esc_html( $row->ip ) . '</div>'
					. esc_html( wp_strip_all_tags( (string) $row->message ) ) . '</div>';
			}
			if ( $d['critical_24h'] > count( $d['critical_rows'] ) ) {
				/* translators: %d: number of further events. */
				$h .= '<div style="font-size:12px;color:#6b7280;">' . esc_html( sprintf( __( 'و%d حدثاً آخر في سجل الأحداث.', 'ejabh-security' ), $d['critical_24h'] - count( $d['critical_rows'] ) ) ) . '</div>';
			}
			$h .= '</div>';
		}

		$h .= '<div style="padding:12px 22px;font-size:13px;color:#374151;line-height:1.9;">';
		$h .= esc_html( sprintf( __( 'آخر فحص ملفات كامل: %s', 'ejabh-security' ), self::when( $d['last_scan'] ) ) ) . '<br>';
		$h .= esc_html(
			$d['watch_on']
				? sprintf( __( 'مراقب الملفات الجديدة: آخر دورة %s', 'ejabh-security' ), self::when( $d['watch_last'] ) )
				: __( 'مراقب الملفات الجديدة: معطّل', 'ejabh-security' )
		) . '<br>';
		$h .= esc_html( sprintf( __( 'عناوين IP محظورة حالياً: %d', 'ejabh-security' ), $d['blocked_ips'] ) );
		if ( $d['watch_held'] ) {
			$h .= '<div style="color:#b91c1c;font-weight:700;margin-top:6px;">' . esc_html__( 'المراقب أوقف الإجراءات التلقائية بعد كثرة النتائج — يحتاج مراجعة من لوحة الحماية.', 'ejabh-security' ) . '</div>';
		}
		$h .= '</div>';

		if ( $d['failed_checks'] ) {
			$h .= '<div style="padding:12px 22px;"><div style="font-weight:700;color:#9a3412;margin-bottom:6px;">' . esc_html__( 'بنود تحصين تحتاج إصلاحاً', 'ejabh-security' ) . '</div><ul style="margin:0;padding-right:18px;font-size:13px;color:#374151;">';
			foreach ( $d['failed_checks'] as $label ) {
				$h .= '<li>' . esc_html( $label ) . '</li>';
			}
			$h .= '</ul></div>';
		}

		$h .= '<div style="padding:18px 22px 24px;text-align:center;"><a href="' . esc_url( $d['dashboard'] ) . '" style="display:inline-block;background:#111827;color:#ffffff;text-decoration:none;padding:10px 22px;border-radius:6px;font-size:14px;">' . esc_html__( 'افتح لوحة الحماية', 'ejabh-security' ) . '</a></div>';
		$h .= '</div><div style="text-align:center;font-size:11px;color:#9ca3af;margin-top:10px;">Ejabh Security</div></div>';

		return $h;
	}
}
