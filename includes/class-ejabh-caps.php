<?php
/**
 * Plugin and theme management lockdown.
 *
 * On a site with several administrators, every one of them is a path to remote
 * code execution: installing a plugin means uploading and running PHP. This
 * class reserves that power for a single designated owner account and denies it
 * to every other administrator.
 *
 * Capabilities are filtered at runtime rather than stripped from the role, so
 * nothing is destroyed and turning the feature off restores the previous state
 * exactly.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Restricts plugin/theme management to the owner account.
 */
class Ejabh_Caps {

	/**
	 * Capabilities that let a user execute new code on the server.
	 *
	 * @return array
	 */
	public static function plugin_caps() {
		return array(
			'install_plugins',
			'upload_plugins',
			'activate_plugins',
			'activate_plugin',
			'deactivate_plugins',
			'deactivate_plugin',
			'update_plugins',
			'delete_plugins',
			'edit_plugins',
			'resume_plugin',
		);
	}

	/**
	 * Theme-management capabilities.
	 *
	 * `edit_theme_options` is deliberately absent: it covers menus, widgets and
	 * the customiser, which editors legitimately need.
	 *
	 * @return array
	 */
	public static function theme_caps() {
		return array(
			'install_themes',
			'upload_themes',
			'update_themes',
			'delete_themes',
			'edit_themes',
			'switch_themes',
			'resume_theme',
		);
	}

	/**
	 * Direct file-editing capabilities.
	 *
	 * @return array
	 */
	public static function file_caps() {
		return array( 'edit_files' );
	}

	/**
	 * Admin screens that manage code.
	 *
	 * @return array
	 */
	public static function guarded_screens() {
		return array(
			'plugins.php',
			'plugin-install.php',
			'plugin-editor.php',
			'theme-install.php',
			'theme-editor.php',
		);
	}

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Ejabh_Settings::get( 'caps_enabled' ) ) {
			return;
		}

		add_filter( 'user_has_cap', array( $this, 'filter_caps' ), 99, 4 );
		add_action( 'admin_init', array( $this, 'guard_screens' ), 1 );
		add_action( 'admin_notices', array( $this, 'notice' ) );
	}

	/**
	 * The full list of locked capabilities, per settings.
	 *
	 * @return array
	 */
	public static function locked_caps() {
		// Memoised: consulted on every capability check.
		static $caps = null;

		if ( null !== $caps ) {
			return $caps;
		}

		$caps = array();

		if ( Ejabh_Settings::get( 'caps_lock_plugins' ) ) {
			$caps = array_merge( $caps, self::plugin_caps() );
		}
		if ( Ejabh_Settings::get( 'caps_lock_themes' ) ) {
			$caps = array_merge( $caps, self::theme_caps() );
		}
		if ( Ejabh_Settings::get( 'caps_lock_file_edit' ) ) {
			$caps = array_merge( $caps, self::file_caps(), array( 'edit_plugins', 'edit_themes' ) );
		}

		$caps = array_values( array_unique( $caps ) );
		return $caps;
	}

	/**
	 * Is this user the designated owner?
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_owner( $user_id ) {
		$owner = Ejabh_Settings::owner_id();
		return $owner > 0 && (int) $user_id === $owner;
	}

	/**
	 * Deny the locked capabilities to everyone but the owner.
	 *
	 * @param array   $allcaps All capabilities of the user.
	 * @param array   $caps    Capabilities being checked.
	 * @param array   $args    Context.
	 * @param WP_User $user    The user.
	 * @return array
	 */
	public function filter_caps( $allcaps, $caps, $args, $user ) {
		if ( ! $user instanceof WP_User || ! $user->ID ) {
			return $allcaps;
		}

		$owner = Ejabh_Settings::owner_id();

		// Fail safe: with no resolvable owner, change nothing.
		if ( $owner <= 0 || (int) $user->ID === $owner ) {
			return $allcaps;
		}

		// Leave WP-CLI and cron alone so maintenance and updates keep working.
		if ( 'cli' === PHP_SAPI || wp_doing_cron() ) {
			return $allcaps;
		}

		foreach ( self::locked_caps() as $cap ) {
			if ( isset( $allcaps[ $cap ] ) ) {
				$allcaps[ $cap ] = false;
			}
		}

		return $allcaps;
	}

	/**
	 * Block and log direct access to the code-management screens.
	 *
	 * Capability filtering already denies these pages; this exists to produce a
	 * clear audit trail and a message that explains what happened.
	 *
	 * @return void
	 */
	public function guard_screens() {
		global $pagenow;

		if ( ! is_user_logged_in() ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( self::is_owner( $user_id ) || Ejabh_Settings::owner_id() <= 0 ) {
			return;
		}

		if ( ! in_array( (string) $pagenow, self::guarded_screens(), true ) ) {
			return;
		}

		// Only relevant for users who would otherwise have had access.
		$user = wp_get_current_user();
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}

		Ejabh_Logger::log(
			'caps_screen_blocked',
			sprintf( 'مُنِع المستخدم %s (#%d) من الوصول إلى %s.', $user->user_login, $user_id, $pagenow ),
			'warning',
			$user_id
		);

		$owner = get_userdata( Ejabh_Settings::owner_id() );

		wp_die(
			esc_html(
				sprintf(
					/* translators: %s: owner display name. */
					__( 'إدارة الإضافات والقوالب مقصورة على حساب واحد على هذا الموقع (%s) بواسطة Ejabh Security. إذا كنت تحتاج تثبيت إضافة، اطلب ذلك منه.', 'ejabh-security' ),
					$owner ? $owner->display_name : __( 'مالك الموقع', 'ejabh-security' )
				)
			),
			esc_html__( 'صلاحية مقيّدة', 'ejabh-security' ),
			array(
				'response'  => 403,
				'back_link' => true,
			)
		);
	}

	/**
	 * Explain the restriction to affected administrators.
	 *
	 * @return void
	 */
	public function notice() {
		if ( ! is_user_logged_in() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return;
		}
		if ( self::is_owner( $user->ID ) || Ejabh_Settings::owner_id() <= 0 ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || 'dashboard' !== $screen->id ) {
			return;
		}

		$owner = get_userdata( Ejabh_Settings::owner_id() );

		printf(
			'<div class="notice notice-info"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %s: owner display name. */
					__( 'ملاحظة أمنية: تثبيت وتفعيل الإضافات والقوالب مقصور على حساب %s. هذا إجراء حماية بعد اختراق الموقع.', 'ejabh-security' ),
					$owner ? $owner->display_name : __( 'مالك الموقع', 'ejabh-security' )
				)
			)
		);
	}
}
