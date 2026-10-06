<?php
/**
 * Login rate limiting and IP blocking.
 *
 * Nothing on this site previously limited password guessing. With XML-RPC open,
 * an attacker could try hundreds of passwords per request; even with XML-RPC
 * closed, wp-login.php will accept attempts indefinitely.
 *
 * Failures are counted per IP inside a rolling window. Cross the threshold and
 * the IP is refused at the `authenticate` filter, before any password check and
 * before any 2FA code is sent — so a lockout cannot be used to spam a user's
 * inbox either.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Throttles authentication attempts.
 */
class Ejabh_Login_Limiter {

	const TABLE = 'dys_sec_blocks';

	/**
	 * Fully qualified table name.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	/**
	 * Create the table.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$table   = self::table();

		dbDelta(
			"CREATE TABLE {$table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				ip VARCHAR(45) NOT NULL,
				failures INT UNSIGNED NOT NULL DEFAULT 0,
				first_failure DATETIME NOT NULL,
				last_failure DATETIME NOT NULL,
				blocked_until DATETIME NULL,
				last_user VARCHAR(180) NOT NULL DEFAULT '',
				PRIMARY KEY  (id),
				UNIQUE KEY ip (ip),
				KEY blocked_until (blocked_until)
			) {$charset};"
		);
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Ejabh_Settings::get( 'login_limit_enabled' ) ) {
			return;
		}

		// Priority 1: refuse before WordPress checks the password.
		add_filter( 'authenticate', array( $this, 'block_if_locked' ), 1, 3 );
		add_action( 'wp_login_failed', array( $this, 'record_failure' ), 10, 1 );
		add_action( 'wp_login', array( $this, 'clear_failures' ), 10, 2 );

		// A wrong 2FA code is a failed authentication too.
		add_action( 'dys_sec_2fa_failed', array( $this, 'record_failure_raw' ) );
	}

	/**
	 * Is this IP exempt from throttling?
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	public static function is_allowlisted( $ip ) {
		if ( ! $ip ) {
			return false;
		}

		foreach ( (array) Ejabh_Settings::get( 'login_ip_allowlist' ) as $entry ) {
			$entry = trim( (string) $entry );
			if ( ! $entry ) {
				continue;
			}

			if ( $entry === $ip ) {
				return true;
			}

			// Simple prefix form, e.g. "198.51.100." matches a whole ISP range.
			if ( substr( $entry, -1 ) === '.' && 0 === strpos( $ip, $entry ) ) {
				return true;
			}

			// CIDR form, e.g. "203.0.113.0/24".
			if ( false !== strpos( $entry, '/' ) && self::ip_in_cidr( $ip, $entry ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * IPv4 CIDR membership test.
	 *
	 * @param string $ip   Address to test.
	 * @param string $cidr Range in a.b.c.d/n form.
	 * @return bool
	 */
	private static function ip_in_cidr( $ip, $cidr ) {
		list( $subnet, $bits ) = array_pad( explode( '/', $cidr, 2 ), 2, '32' );

		$ip_long     = ip2long( $ip );
		$subnet_long = ip2long( $subnet );
		$bits        = (int) $bits;

		if ( false === $ip_long || false === $subnet_long || $bits < 0 || $bits > 32 ) {
			return false;
		}
		if ( 0 === $bits ) {
			return true;
		}

		$mask = -1 << ( 32 - $bits );
		return ( $ip_long & $mask ) === ( $subnet_long & $mask );
	}

	/**
	 * Current block record for an IP, if any.
	 *
	 * @param string $ip Client IP.
	 * @return object|null
	 */
	public static function get_record( $ip ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE ip = %s", $ip ) );
	}

	/**
	 * Seconds remaining on a block, or 0.
	 *
	 * @param string $ip Client IP.
	 * @return int
	 */
	public static function blocked_for( $ip ) {
		$row = self::get_record( $ip );
		if ( ! $row || empty( $row->blocked_until ) ) {
			return 0;
		}

		$until = strtotime( $row->blocked_until . ' UTC' );
		return $until && $until > time() ? $until - time() : 0;
	}

	/**
	 * Refuse authentication from a blocked IP.
	 *
	 * @param null|WP_User|WP_Error $user     Current result.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return null|WP_User|WP_Error
	 */
	public function block_if_locked( $user, $username = '', $password = '' ) {
		// Nothing was submitted; let WordPress render the form.
		if ( '' === $username && '' === $password ) {
			return $user;
		}

		$ip = Ejabh_Logger::client_ip();
		if ( ! $ip || self::is_allowlisted( $ip ) ) {
			return $user;
		}

		$remaining = self::blocked_for( $ip );
		if ( $remaining <= 0 ) {
			return $user;
		}

		$minutes = max( 1, (int) ceil( $remaining / 60 ) );

		return new WP_Error(
			'dys_sec_ip_blocked',
			sprintf(
				/* translators: %d: minutes remaining. */
				__( '<strong>تم حظر محاولات الدخول مؤقتاً</strong> من عنوانك بسبب عدة محاولات فاشلة. أعد المحاولة بعد %d دقيقة.', 'ejabh-security' ),
				$minutes
			)
		);
	}

	/**
	 * Count a failed login.
	 *
	 * @param string $username Attempted username.
	 * @return void
	 */
	public function record_failure( $username = '' ) {
		$this->register( (string) $username );
	}

	/**
	 * Count a failure raised by another component (e.g. a wrong 2FA code).
	 *
	 * @param mixed $context User object or login string.
	 * @return void
	 */
	public function record_failure_raw( $context = '' ) {
		$login = $context instanceof WP_User ? $context->user_login : (string) $context;
		$this->register( $login );
	}

	/**
	 * Increment the counter and block once the threshold is crossed.
	 *
	 * @param string $username Attempted username.
	 * @return void
	 */
	private function register( $username ) {
		global $wpdb;

		$ip = Ejabh_Logger::client_ip();
		if ( ! $ip || self::is_allowlisted( $ip ) ) {
			return;
		}

		$table   = self::table();
		$now     = current_time( 'mysql', true );
		$max     = max( 1, (int) Ejabh_Settings::get( 'login_max_attempts' ) );
		$window  = max( 1, (int) Ejabh_Settings::get( 'login_window_mins' ) ) * MINUTE_IN_SECONDS;
		$lockout = max( 1, (int) Ejabh_Settings::get( 'login_lockout_mins' ) ) * MINUTE_IN_SECONDS;

		$row = self::get_record( $ip );

		// Outside the rolling window the count starts again.
		$restart = true;
		if ( $row ) {
			$first   = strtotime( $row->first_failure . ' UTC' );
			$restart = ! $first || ( time() - $first ) > $window;
		}

		$failures = ( $row && ! $restart ) ? (int) $row->failures + 1 : 1;
		$blocked  = null;

		if ( $failures >= $max ) {
			$blocked = gmdate( 'Y-m-d H:i:s', time() + $lockout );
		}

		if ( $row ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->update(
				$table,
				array(
					'failures'      => $failures,
					'first_failure' => $restart ? $now : $row->first_failure,
					'last_failure'  => $now,
					'blocked_until' => $blocked,
					'last_user'     => substr( $username, 0, 180 ),
				),
				array( 'ip' => $ip ),
				array( '%d', '%s', '%s', '%s', '%s' ),
				array( '%s' )
			);
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert(
				$table,
				array(
					'ip'            => $ip,
					'failures'      => $failures,
					'first_failure' => $now,
					'last_failure'  => $now,
					'blocked_until' => $blocked,
					'last_user'     => substr( $username, 0, 180 ),
				),
				array( '%s', '%d', '%s', '%s', '%s', '%s' )
			);
		}

		if ( $blocked ) {
			Ejabh_Logger::log(
				'login_ip_blocked',
				sprintf(
					'حُظر العنوان %s بعد %d محاولة دخول فاشلة (آخر اسم مستخدم مُجرَّب: %s). مدة الحظر %d دقيقة.',
					$ip,
					$failures,
					$username ? $username : '—',
					(int) Ejabh_Settings::get( 'login_lockout_mins' )
				),
				'critical'
			);
		} else {
			Ejabh_Logger::log(
				'login_failed',
				sprintf( 'محاولة دخول فاشلة للاسم "%s" من %s (%d/%d).', $username ? $username : '—', $ip, $failures, $max ),
				'info'
			);
		}
	}

	/**
	 * A successful login clears the counter for that IP.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User.
	 * @return void
	 */
	public function clear_failures( $user_login = '', $user = null ) {
		global $wpdb;

		$ip = Ejabh_Logger::client_ip();
		if ( ! $ip ) {
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->delete( self::table(), array( 'ip' => $ip ), array( '%s' ) );
	}

	/**
	 * Lift a block manually.
	 *
	 * @param string $ip Address to release.
	 * @return void
	 */
	public static function unblock( $ip ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->delete( self::table(), array( 'ip' => $ip ), array( '%s' ) );
		Ejabh_Logger::log( 'login_ip_unblocked', sprintf( 'رُفع الحظر يدوياً عن العنوان %s.', $ip ), 'warning' );
	}

	/**
	 * Rows for the admin screen, most recent first.
	 *
	 * @param int $limit Max rows.
	 * @return array
	 */
	public static function recent( $limit = 100 ) {
		global $wpdb;
		$table = self::table();
		$limit = max( 1, min( 500, (int) $limit ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY last_failure DESC LIMIT %d", $limit ) );
	}

	/**
	 * How many IPs are blocked right now.
	 *
	 * @return int
	 */
	public static function active_block_count() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE blocked_until IS NOT NULL AND blocked_until > %s", current_time( 'mysql', true ) ) );
	}

	/**
	 * Drop expired rows.
	 *
	 * @return void
	 */
	public static function prune() {
		global $wpdb;
		$table  = self::table();
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE last_failure < %s AND (blocked_until IS NULL OR blocked_until < %s)", $cutoff, gmdate( 'Y-m-d H:i:s' ) ) );
	}
}
