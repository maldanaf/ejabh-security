<?php
/**
 * Unattended scheduled scanning.
 *
 * A scan nobody remembers to run is not a control. This drives the file,
 * database and integrity scanners to completion in the background and mails a
 * summary — but only reports what is *new* since the previous run, so the alert
 * stays meaningful instead of repeating the same known findings every week.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Cron-driven scanning.
 */
class Ejabh_Scheduler {

	const HOOK           = 'dys_sec_scheduled_scan';
	const RUNNER_HOOK    = 'dys_sec_scan_runner';
	const LAST_SUMMARY   = 'dys_sec_last_summary';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( self::HOOK, array( $this, 'begin' ) );
		add_action( self::RUNNER_HOOK, array( $this, 'advance' ) );
	}

	/**
	 * (Re)schedule according to the current settings.
	 *
	 * @return void
	 */
	public static function reschedule() {
		$existing = wp_next_scheduled( self::HOOK );

		if ( ! Ejabh_Settings::get( 'sched_scan_enabled' ) ) {
			if ( $existing ) {
				wp_unschedule_event( $existing, self::HOOK );
			}
			return;
		}

		$freq = (string) Ejabh_Settings::get( 'sched_scan_freq' );
		if ( ! in_array( $freq, array( 'daily', 'weekly' ), true ) ) {
			$freq = 'weekly';
		}

		// Only reschedule when the interval actually changed.
		if ( $existing ) {
			$event = wp_get_scheduled_event( self::HOOK );
			if ( $event && isset( $event->schedule ) && $event->schedule === $freq ) {
				return;
			}
			wp_unschedule_event( $existing, self::HOOK );
		}

		// Start in the small hours rather than immediately.
		wp_schedule_event( strtotime( 'tomorrow 03:30' ), $freq, self::HOOK );
	}

	/**
	 * Remove all scheduled work.
	 *
	 * @return void
	 */
	public static function unschedule() {
		foreach ( array( self::HOOK, self::RUNNER_HOOK ) as $hook ) {
			$timestamp = wp_next_scheduled( $hook );
			while ( $timestamp ) {
				wp_unschedule_event( $timestamp, $hook );
				$timestamp = wp_next_scheduled( $hook );
			}
		}
	}

	/**
	 * Kick off a full unattended scan.
	 *
	 * @return void
	 */
	public function begin() {
		if ( ! Ejabh_Settings::get( 'sched_scan_enabled' ) ) {
			return;
		}

		// Snapshot the current picture so we can diff against it afterwards.
		update_option( self::LAST_SUMMARY, self::snapshot(), false );

		Ejabh_File_Scanner::start();
		Ejabh_DB_Scanner::start();

		if ( Ejabh_Settings::get( 'integrity_enabled' ) ) {
			Ejabh_Integrity::start();
		}

		Ejabh_Logger::log( 'sched_scan_started', 'بدأ الفحص التلقائي المجدول.', 'info' );

		$this->queue_next_step();
	}

	/**
	 * Run one slice of each in-progress scanner, then requeue if needed.
	 *
	 * Cron requests are individually short-lived, so the work is spread over
	 * many one-minute wake-ups rather than attempted in a single request.
	 *
	 * @return void
	 */
	public function advance() {
		$busy = false;

		if ( 'scanning' === Ejabh_File_Scanner::state()['status'] ) {
			Ejabh_File_Scanner::step();
			$busy = true;
		}
		if ( 'scanning' === Ejabh_DB_Scanner::state()['status'] ) {
			Ejabh_DB_Scanner::step();
			$busy = true;
		}
		if ( 'scanning' === Ejabh_Integrity::state()['status'] ) {
			Ejabh_Integrity::step();
			$busy = true;
		}

		if ( $busy ) {
			$this->queue_next_step();
			return;
		}

		$this->finish();
	}

	/**
	 * Schedule the next slice a minute out.
	 *
	 * @return void
	 */
	private function queue_next_step() {
		if ( ! wp_next_scheduled( self::RUNNER_HOOK ) ) {
			wp_schedule_single_event( time() + 60, self::RUNNER_HOOK );
		}
	}

	/**
	 * Compare against the pre-scan snapshot and mail the difference.
	 *
	 * @return void
	 */
	private function finish() {
		$before = get_option( self::LAST_SUMMARY, array() );
		$before = is_array( $before ) ? $before : array();
		$after  = self::snapshot();

		$new_critical = max( 0, (int) ( $after['critical'] ?? 0 ) - (int) ( $before['critical'] ?? 0 ) );
		$new_high     = max( 0, (int) ( $after['high'] ?? 0 ) - (int) ( $before['high'] ?? 0 ) );

		// File changes are reported on their own terms: a brand-new PHP file is
		// worth an e-mail even when the severity totals happen not to move.
		$file_state = Ejabh_File_Scanner::state();
		$changes    = array(
			'new'     => (int) ( $file_state['fim_new'] ?? 0 ),
			'changed' => (int) ( $file_state['fim_changed'] ?? 0 ),
			'gone'    => (int) ( $file_state['fim_gone'] ?? 0 ),
		);
		$changed_any = ( $changes['new'] + $changes['changed'] + $changes['gone'] ) > 0;

		update_option( self::LAST_SUMMARY, $after, false );

		Ejabh_Logger::log(
			'sched_scan_finished',
			sprintf(
				'انتهى الفحص التلقائي: %d حرج، %d عالي (الجديد: %d حرج، %d عالي). تغيّرات الملفات: %d جديد، %d مُعدَّل، %d محذوف.',
				(int) $after['critical'],
				(int) $after['high'],
				$new_critical,
				$new_high,
				$changes['new'],
				$changes['changed'],
				$changes['gone']
			),
			( $new_critical > 0 || $changes['new'] > 0 ) ? 'critical' : 'info'
		);

		// Stay quiet when nothing changed; a periodic "all clear" trains people
		// to ignore the mail, and the dashboard already shows current state.
		if ( $new_critical || $new_high || $changed_any ) {
			Ejabh_Mailer::send_scan_summary( $after, $new_critical, $new_high, $changes, self::changed_file_list() );
		}
	}

	/**
	 * The file-change findings from the most recent scan, for the e-mail body.
	 *
	 * @param int $limit Maximum paths to list.
	 * @return array
	 */
	private static function changed_file_list( $limit = 25 ) {
		global $wpdb;

		$table = Ejabh_Findings::table();
		$rules = array( 'fim_new_code_file', 'fim_modified_code_file', 'fim_deleted_code_file' );
		$in    = implode( ',', array_fill( 0, count( $rules ), '%s' ) );

		$args = $rules;
		$args[] = (int) $limit;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT rule, target FROM {$table} WHERE rule IN ({$in}) ORDER BY FIELD(rule,'fim_new_code_file','fim_modified_code_file','fim_deleted_code_file'), id ASC LIMIT %d", $args )
		);

		$out = array();
		foreach ( (array) $rows as $row ) {
			$prefix = 'fim_new_code_file' === $row->rule
				? __( 'جديد', 'ejabh-security' )
				: ( 'fim_modified_code_file' === $row->rule ? __( 'مُعدَّل', 'ejabh-security' ) : __( 'محذوف', 'ejabh-security' ) );

			$out[] = sprintf( '[%s] %s', $prefix, $row->target );
		}

		return $out;
	}

	/**
	 * Current finding counts plus a little context.
	 *
	 * @return array
	 */
	private static function snapshot() {
		$counts = Ejabh_Findings::counts();

		return array(
			'critical' => (int) $counts['critical'],
			'high'     => (int) $counts['high'],
			'medium'   => (int) $counts['medium'],
			'low'      => (int) $counts['low'],
			'at'       => time(),
		);
	}
}
