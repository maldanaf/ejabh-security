<?php
/**
 * Active session monitoring.
 *
 * WordPress already records IP, user agent and login time for every session in
 * the `session_tokens` user meta. This class surfaces that data for every user
 * and lets an administrator revoke sessions individually or in bulk.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Reads and revokes WordPress login sessions.
 */
class Ejabh_Sessions {

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		add_action( 'admin_post_dys_sec_session_action', array( $this, 'handle_action' ) );
	}

	/**
	 * Every active session on the site, newest login first.
	 *
	 * @param array $args Optional filters: user_id, role, only_privileged.
	 * @return array List of session rows.
	 */
	public static function all( array $args = array() ) {
		global $wpdb;

		$args = wp_parse_args(
			$args,
			array(
				'user_id' => 0,
				'role'    => '',
			)
		);

		if ( $args['user_id'] ) {
			$user_ids = array( (int) $args['user_id'] );
		} else {
			// Only users that actually have the meta — cheap and avoids loading all users.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$user_ids = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s",
					'session_tokens'
				)
			);
			$user_ids = array_map( 'intval', (array) $user_ids );
		}

		$current_verifier = self::current_verifier();
		$rows             = array();
		$now              = time();

		foreach ( $user_ids as $user_id ) {
			$user = get_userdata( $user_id );
			if ( ! $user ) {
				continue;
			}

			if ( $args['role'] && ! in_array( $args['role'], (array) $user->roles, true ) ) {
				continue;
			}

			$sessions = get_user_meta( $user_id, 'session_tokens', true );
			if ( ! is_array( $sessions ) ) {
				continue;
			}

			foreach ( $sessions as $verifier => $session ) {
				if ( ! is_array( $session ) ) {
					continue;
				}

				$expiration = isset( $session['expiration'] ) ? (int) $session['expiration'] : 0;
				$login      = isset( $session['login'] ) ? (int) $session['login'] : 0;

				$rows[] = array(
					'user_id'    => $user_id,
					'user_login' => $user->user_login,
					'display'    => $user->display_name,
					'email'      => $user->user_email,
					'roles'      => (array) $user->roles,
					'is_admin'   => in_array( 'administrator', (array) $user->roles, true ),
					'verifier'   => (string) $verifier,
					'ip'         => isset( $session['ip'] ) ? (string) $session['ip'] : '',
					'ua'         => isset( $session['ua'] ) ? (string) $session['ua'] : '',
					'login'      => $login,
					'expiration' => $expiration,
					'expired'    => $expiration > 0 && $expiration < $now,
					'is_current' => $current_verifier && hash_equals( $current_verifier, (string) $verifier ),
				);
			}
		}

		usort(
			$rows,
			static function ( $a, $b ) {
				return $b['login'] <=> $a['login'];
			}
		);

		return $rows;
	}

	/**
	 * Summary counts for the dashboard.
	 *
	 * @return array
	 */
	public static function summary() {
		$rows  = self::all();
		$out   = array(
			'total'      => count( $rows ),
			'admins'     => 0,
			'users'      => 0,
			'expired'    => 0,
			'unique_ips' => 0,
		);
		$users = array();
		$ips   = array();

		foreach ( $rows as $row ) {
			if ( $row['is_admin'] ) {
				++$out['admins'];
			}
			if ( $row['expired'] ) {
				++$out['expired'];
			}
			$users[ $row['user_id'] ] = true;
			if ( $row['ip'] ) {
				$ips[ $row['ip'] ] = true;
			}
		}

		$out['users']      = count( $users );
		$out['unique_ips'] = count( $ips );

		return $out;
	}

	/**
	 * Verifier of the session the current request is using.
	 *
	 * @return string
	 */
	private static function current_verifier() {
		if ( ! is_user_logged_in() ) {
			return '';
		}
		$token = wp_get_session_token();
		return $token ? hash( 'sha256', $token ) : '';
	}

	/**
	 * Revoke one session by its verifier.
	 *
	 * The public WP_Session_Tokens API can only destroy by raw token, which the
	 * server never stores, so the meta is edited directly.
	 *
	 * @param int    $user_id  Owner of the session.
	 * @param string $verifier Session verifier (meta array key).
	 * @return bool
	 */
	public static function revoke( $user_id, $verifier ) {
		$user_id  = (int) $user_id;
		$sessions = get_user_meta( $user_id, 'session_tokens', true );

		if ( ! is_array( $sessions ) || ! isset( $sessions[ $verifier ] ) ) {
			return false;
		}

		unset( $sessions[ $verifier ] );

		if ( $sessions ) {
			update_user_meta( $user_id, 'session_tokens', $sessions );
		} else {
			delete_user_meta( $user_id, 'session_tokens' );
		}

		return true;
	}

	/**
	 * Revoke every session for one user.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	public static function revoke_all_for_user( $user_id ) {
		$manager = WP_Session_Tokens::get_instance( (int) $user_id );
		$manager->destroy_all();
	}

	/**
	 * Revoke every session on the site.
	 *
	 * @return void
	 */
	public static function revoke_everything() {
		WP_Session_Tokens::destroy_all_for_all_users();
	}

	/**
	 * Handle the admin-post actions from the sessions screen.
	 *
	 * @return void
	 */
	public function handle_action() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'ليست لديك صلاحية لهذا الإجراء.', 'ejabh-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'dys_sec_sessions' );

		$what    = isset( $_POST['what'] ) ? sanitize_key( wp_unslash( $_POST['what'] ) ) : '';
		$user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0;
		$notice  = 'none';

		switch ( $what ) {
			case 'revoke_one':
				$verifier = isset( $_POST['verifier'] ) ? preg_replace( '/[^a-f0-9]/', '', wp_unslash( $_POST['verifier'] ) ) : '';
				if ( $user_id && $verifier && self::revoke( $user_id, $verifier ) ) {
					$user = get_userdata( $user_id );
					Ejabh_Logger::log(
						'session_revoked',
						sprintf( 'أُلغيت جلسة واحدة للمستخدم %s (#%d).', $user ? $user->user_login : '?', $user_id ),
						'info'
					);
					$notice = 'revoked_one';
				}
				break;

			case 'revoke_user':
				if ( $user_id ) {
					self::revoke_all_for_user( $user_id );
					$user = get_userdata( $user_id );
					Ejabh_Logger::log(
						'sessions_revoked_user',
						sprintf( 'أُلغيت كل جلسات المستخدم %s (#%d).', $user ? $user->user_login : '?', $user_id ),
						'warning'
					);
					$notice = 'revoked_user';
				}
				break;

			case 'revoke_all':
				self::revoke_everything();
				Ejabh_Logger::log(
					'sessions_revoked_all',
					'أُلغيت كل جلسات كل المستخدمين على الموقع.',
					'critical'
				);
				$notice = 'revoked_all';
				break;
		}

		wp_safe_redirect(
			add_query_arg(
				'dys_notice',
				$notice,
				admin_url( 'admin.php?page=ejabh-security-sessions' )
			)
		);
		exit;
	}

	/**
	 * Turn a user-agent string into something readable.
	 *
	 * @param string $ua Raw user agent.
	 * @return string
	 */
	public static function pretty_ua( $ua ) {
		if ( ! $ua ) {
			return __( 'غير معروف', 'ejabh-security' );
		}

		$browser = __( 'متصفح غير معروف', 'ejabh-security' );
		$os      = '';

		$browsers = array(
			'Edg'      => 'Edge',
			'OPR'      => 'Opera',
			'Chrome'   => 'Chrome',
			'Firefox'  => 'Firefox',
			'Safari'   => 'Safari',
			'MSIE'     => 'Internet Explorer',
			'Trident'  => 'Internet Explorer',
			'curl'     => 'curl',
			'wget'     => 'wget',
			'python'   => 'Python script',
			'Go-http'  => 'Go script',
			'WordPress'=> 'WordPress',
		);
		foreach ( $browsers as $needle => $label ) {
			if ( false !== stripos( $ua, $needle ) ) {
				$browser = $label;
				if ( preg_match( '#' . preg_quote( $needle, '#' ) . '[/ ]([0-9]+)#i', $ua, $m ) ) {
					$browser .= ' ' . $m[1];
				}
				break;
			}
		}

		$systems = array(
			'Windows NT 10' => 'Windows 10/11',
			'Windows NT 6.3'=> 'Windows 8.1',
			'Windows'       => 'Windows',
			'iPhone'        => 'iPhone',
			'iPad'          => 'iPad',
			'Android'       => 'Android',
			'Mac OS X'      => 'macOS',
			'Linux'         => 'Linux',
		);
		foreach ( $systems as $needle => $label ) {
			if ( false !== stripos( $ua, $needle ) ) {
				$os = $label;
				break;
			}
		}

		return $os ? $browser . ' — ' . $os : $browser;
	}
}
