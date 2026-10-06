<?php
/**
 * Account protection.
 *
 * Three related defences:
 *
 *  - Administrator lockdown. Creating an admin account is precisely what the
 *    attacker did on 2026-07-22, twice, 47 minutes apart. Only the owner may
 *    mint or promote an administrator; anything else is reverted and reported.
 *  - New-location alerts. A privileged login from an unseen IP sends mail
 *    immediately, so the next intrusion is noticed in minutes, not days.
 *  - Enumeration blocking. `?author=1` and the REST users endpoint hand out a
 *    valid username list to anyone who asks, which is half of a brute force.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Guards privileged accounts.
 */
class Ejabh_User_Guard {

	/** Stores the set of admin IDs we consider legitimate. */
	const KNOWN_ADMINS_OPTION = 'dys_sec_known_admins';

	/** User meta holding previously seen login IPs. */
	const SEEN_IPS_META = 'dys_sec_seen_ips';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( Ejabh_Settings::get( 'admin_guard_enabled' ) ) {
			// Remove 'administrator' from the roles a non-owner may assign. This
			// covers the user-edit screens and wp_ensure_editable_role().
			add_filter( 'editable_roles', array( $this, 'filter_editable_roles' ) );

			// Catch anything that slipped past the UI, including direct calls.
			add_action( 'set_user_role', array( $this, 'audit_role_change' ), 10, 3 );
			add_action( 'add_user_role', array( $this, 'audit_role_added' ), 10, 2 );
			add_action( 'user_register', array( $this, 'audit_new_user' ), 999 );

			// Detect admins created by a route that fires no hook at all
			// (a direct database write, which is what a shell would do).
			add_action( 'admin_init', array( $this, 'reconcile_admins' ) );
		}

		if ( Ejabh_Settings::get( 'new_ip_alert_enabled' ) ) {
			add_action( 'wp_login', array( $this, 'check_login_location' ), 20, 2 );
			add_action( 'dys_sec_2fa_passed', array( $this, 'check_login_location_2fa' ) );
		}

		if ( Ejabh_Settings::get( 'enum_block_enabled' ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_scan' ) );
			add_filter( 'rest_endpoints', array( $this, 'block_rest_users' ) );
			add_filter( 'rest_authentication_errors', array( $this, 'guard_rest_users' ), 20 );
			add_filter( 'wp_sitemaps_add_provider', array( $this, 'remove_author_sitemap' ), 10, 2 );
			add_filter( 'oembed_response_data', array( $this, 'strip_oembed_author' ) );
		}
	}

	/* ---------------------------------------------------------------------
	 * Administrator lockdown
	 * ------------------------------------------------------------------ */

	/**
	 * Is the current actor allowed to mint administrators?
	 *
	 * @return bool
	 */
	private function actor_may_promote() {
		// Leave automation alone: WP-CLI and cron have no logged-in identity and
		// blocking them would break legitimate maintenance.
		if ( 'cli' === PHP_SAPI || wp_doing_cron() ) {
			return true;
		}

		$owner = Ejabh_Settings::owner_id();
		if ( $owner <= 0 ) {
			return true;
		}

		return get_current_user_id() === $owner;
	}

	/**
	 * Hide the administrator role from everyone but the owner.
	 *
	 * @param array $roles Assignable roles.
	 * @return array
	 */
	public function filter_editable_roles( $roles ) {
		if ( $this->actor_may_promote() ) {
			return $roles;
		}
		unset( $roles['administrator'] );
		return $roles;
	}

	/**
	 * Revert an unauthorised promotion to administrator.
	 *
	 * @param int    $user_id   Affected user.
	 * @param string $role      New role.
	 * @param array  $old_roles Previous roles.
	 * @return void
	 */
	public function audit_role_change( $user_id, $role, $old_roles ) {
		if ( 'administrator' !== $role ) {
			return;
		}
		if ( in_array( 'administrator', (array) $old_roles, true ) ) {
			return; // No change.
		}
		if ( $this->actor_may_promote() ) {
			$this->remember_admins();
			return;
		}

		$this->reject_promotion( $user_id, (array) $old_roles );
	}

	/**
	 * Revert an unauthorised additive administrator role.
	 *
	 * @param int    $user_id User.
	 * @param string $role    Role added.
	 * @return void
	 */
	public function audit_role_added( $user_id, $role ) {
		if ( 'administrator' !== $role || $this->actor_may_promote() ) {
			return;
		}

		$user = get_userdata( $user_id );
		if ( $user ) {
			$user->remove_role( 'administrator' );
		}

		$this->alert_blocked_promotion( $user_id, 'add_user_role' );
	}

	/**
	 * Catch a freshly registered administrator.
	 *
	 * @param int $user_id New user.
	 * @return void
	 */
	public function audit_new_user( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user || ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}
		if ( $this->actor_may_promote() ) {
			$this->remember_admins();
			return;
		}

		$this->reject_promotion( $user_id, array( get_option( 'default_role', 'subscriber' ) ) );
	}

	/**
	 * Demote a user and raise the alarm.
	 *
	 * @param int   $user_id   Affected user.
	 * @param array $old_roles Roles to restore.
	 * @return void
	 */
	private function reject_promotion( $user_id, array $old_roles ) {
		if ( ! Ejabh_Settings::get( 'admin_guard_revert' ) ) {
			$this->alert_blocked_promotion( $user_id, 'detected_only' );
			return;
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$restore = '';
		foreach ( $old_roles as $role ) {
			if ( $role && 'administrator' !== $role ) {
				$restore = $role;
				break;
			}
		}
		if ( ! $restore ) {
			$restore = (string) get_option( 'default_role', 'subscriber' );
		}

		// remove_filter guard: set_role() fires set_user_role again.
		remove_action( 'set_user_role', array( $this, 'audit_role_change' ), 10 );
		$user->set_role( $restore );
		add_action( 'set_user_role', array( $this, 'audit_role_change' ), 10, 3 );

		$this->alert_blocked_promotion( $user_id, 'reverted_to_' . $restore );
	}

	/**
	 * Log and mail a blocked promotion.
	 *
	 * @param int    $user_id Affected user.
	 * @param string $action  What was done.
	 * @return void
	 */
	private function alert_blocked_promotion( $user_id, $action ) {
		$user  = get_userdata( $user_id );
		$actor = wp_get_current_user();

		Ejabh_Logger::log(
			'admin_promotion_blocked',
			sprintf(
				'مُنِعت ترقية الحساب %s (#%d) إلى مدير. المنفِّذ: %s (#%d). الإجراء: %s.',
				$user ? $user->user_login : '?',
				$user_id,
				$actor && $actor->ID ? $actor->user_login : 'غير معروف',
				$actor ? $actor->ID : 0,
				$action
			),
			'critical',
			$user_id
		);
	}

	/**
	 * Snapshot the current administrator set as legitimate.
	 *
	 * @return void
	 */
	public function remember_admins() {
		$ids = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
			)
		);
		update_option( self::KNOWN_ADMINS_OPTION, array_map( 'intval', (array) $ids ), false );
	}

	/**
	 * Compare the live administrator set against the known-good snapshot.
	 *
	 * This is the backstop for an admin inserted straight into the database,
	 * which fires none of WordPress's hooks.
	 *
	 * @return void
	 */
	public function reconcile_admins() {
		if ( get_transient( 'dys_sec_admins_checked' ) ) {
			return;
		}
		set_transient( 'dys_sec_admins_checked', 1, 5 * MINUTE_IN_SECONDS );

		$known = get_option( self::KNOWN_ADMINS_OPTION, null );

		if ( ! is_array( $known ) ) {
			// First run: adopt the current state as the baseline.
			$this->remember_admins();
			return;
		}

		$current = array_map(
			'intval',
			(array) get_users(
				array(
					'role'   => 'administrator',
					'fields' => 'ID',
				)
			)
		);

		$unexpected = array_diff( $current, $known );

		foreach ( $unexpected as $user_id ) {
			$user = get_userdata( $user_id );
			Ejabh_Logger::log(
				'unexpected_admin_detected',
				sprintf(
					'⚠️ ظهر حساب مدير غير مُسجَّل في القائمة المعتمدة: %s <%s> (#%d)، أُنشئ في %s. إن لم تكن أنشأته، فالموقع مخترق الآن.',
					$user ? $user->user_login : '?',
					$user ? $user->user_email : '?',
					$user_id,
					$user ? $user->user_registered : '?'
				),
				'critical',
				$user_id
			);
		}

		// Keep the snapshot current so the same account is not reported forever;
		// it has been logged and mailed once, which is the point.
		if ( $unexpected || array_diff( $known, $current ) ) {
			$this->remember_admins();
		}
	}

	/* ---------------------------------------------------------------------
	 * New-location login alerts
	 * ------------------------------------------------------------------ */

	/**
	 * Handle the alert after two-factor completes.
	 *
	 * @param WP_User $user Authenticated user.
	 * @return void
	 */
	public function check_login_location_2fa( $user ) {
		$this->check_login_location( $user instanceof WP_User ? $user->user_login : '', $user );
	}

	/**
	 * Mail the user when a privileged login comes from an unseen IP.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 * @return void
	 */
	public function check_login_location( $user_login, $user = null ) {
		if ( ! $user instanceof WP_User ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $user || ! $user->ID ) {
			return;
		}

		// When 2FA is on, wp_login fires before the challenge is passed. Wait for
		// the dys_sec_2fa_passed signal instead so we do not alert on a login
		// that never actually completed.
		if ( Ejabh_Settings::get( '2fa_enabled' ) && ! Ejabh_2FA::bypassed() && 'dys_sec_2fa_passed' !== current_action() ) {
			return;
		}

		$watched = (array) Ejabh_Settings::get( 'new_ip_alert_roles' );
		if ( $watched && ! array_intersect( $watched, (array) $user->roles ) ) {
			return;
		}

		$ip = Ejabh_Logger::client_ip();
		if ( ! $ip ) {
			return;
		}

		$seen = get_user_meta( $user->ID, self::SEEN_IPS_META, true );
		$seen = is_array( $seen ) ? $seen : array();

		if ( isset( $seen[ $ip ] ) ) {
			$seen[ $ip ] = time();
			update_user_meta( $user->ID, self::SEEN_IPS_META, $seen );
			return;
		}

		$first_ever = empty( $seen );

		$seen[ $ip ] = time();
		if ( count( $seen ) > 40 ) {
			asort( $seen );
			$seen = array_slice( $seen, -40, null, true );
		}
		update_user_meta( $user->ID, self::SEEN_IPS_META, $seen );

		// The first recorded login establishes the baseline; alerting on it would
		// just be noise for every existing user.
		if ( $first_ever ) {
			return;
		}

		Ejabh_Logger::log(
			'login_new_ip',
			sprintf( 'دخول للحساب %s (#%d) من عنوان جديد: %s', $user->user_login, $user->ID, $ip ),
			'warning',
			$user->ID
		);

		Ejabh_Mailer::send_new_location_alert( $user, $ip );
	}

	/* ---------------------------------------------------------------------
	 * Enumeration blocking
	 * ------------------------------------------------------------------ */

	/**
	 * Refuse `?author=N` probing on the front end.
	 *
	 * @return void
	 */
	public function block_author_scan() {
		if ( is_user_logged_in() || is_admin() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$probing = isset( $_GET['author'] ) && '' !== $_GET['author'];

		if ( ! $probing && ! is_author() ) {
			return;
		}

		Ejabh_Logger::log(
			'enum_blocked',
			sprintf( 'مُنِعت محاولة تعداد المستخدمين عبر author من العنوان %s.', Ejabh_Logger::client_ip() ),
			'info'
		);

		wp_safe_redirect( home_url( '/' ), 301 );
		exit;
	}

	/**
	 * Remove the users REST routes for unauthenticated callers.
	 *
	 * @param array $endpoints REST endpoints.
	 * @return array
	 */
	public function block_rest_users( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		return $endpoints;
	}

	/**
	 * Belt and braces: reject an unauthenticated request to the users route.
	 *
	 * @param WP_Error|null|true $result Current auth result.
	 * @return WP_Error|null|true
	 */
	public function guard_rest_users( $result ) {
		if ( ! empty( $result ) || is_user_logged_in() ) {
			return $result;
		}

		$route = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? (string) $GLOBALS['wp']->query_vars['rest_route'] : '';
		if ( '' === $route && isset( $_SERVER['REQUEST_URI'] ) ) {
			$route = (string) wp_unslash( $_SERVER['REQUEST_URI'] );
		}

		if ( ! preg_match( '#/wp/v2/users\b#', $route ) ) {
			return $result;
		}

		return new WP_Error(
			'dys_rest_users_blocked',
			__( 'قائمة المستخدمين غير متاحة للزوار.', 'ejabh-security' ),
			array( 'status' => 401 )
		);
	}

	/**
	 * Drop the author sitemap, which also lists every username.
	 *
	 * @param mixed  $provider Sitemap provider.
	 * @param string $name     Provider name.
	 * @return mixed False to remove.
	 */
	public function remove_author_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Remove author identity from oEmbed responses.
	 *
	 * @param array $data Response data.
	 * @return array
	 */
	public function strip_oembed_author( $data ) {
		if ( is_array( $data ) ) {
			unset( $data['author_name'], $data['author_url'] );
		}
		return $data;
	}
}
