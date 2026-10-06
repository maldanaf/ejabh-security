<?php
/**
 * Plugin Name:       Ejabh Security
 * Plugin URI:        https://github.com/maldanaf/ejabh-security
 * Description:       طبقة حماية مخصصة: مصادقة ثنائية إجبارية بالبريد، مراقبة الجلسات النشطة، فحص ملفات الاستضافة وقاعدة البيانات بحثاً عن الأبواب الخلفية وصفحات التصيّد، اعتراض الشِلّات لحظة رفعها، حظر إضافات مدير الملفات، تقييد إدارة الإضافات على مالك واحد، وتقرير أمان يومي لعدة مستلمين.
 * Version:           2.0.0
 * Requires at least: 6.4
 * Tested up to:      7.0
 * Requires PHP:      7.4
 * Author:            Ejabh — Security
 * License:           GPL-2.0-or-later
 * Text Domain:       ejabh-security
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

define( 'EJABH_SEC_VERSION', '2.0.0' );
define( 'EJABH_SEC_FILE', __FILE__ );
define( 'EJABH_SEC_DIR', plugin_dir_path( __FILE__ ) );
define( 'EJABH_SEC_URL', plugin_dir_url( __FILE__ ) );
define( 'EJABH_SEC_BASENAME', plugin_basename( __FILE__ ) );

/**
 * The plugin before it was renamed. Ejabh Security takes over from it on
 * activation; both must never run together (2FA would challenge twice).
 */
define( 'EJABH_SEC_LEGACY_BASENAME', 'dys-security/dys-security.php' );

/*
 * Storage note: options, transients, user meta, cron hooks and tables keep the
 * `dys_sec_` prefix of the pre-rename plugin. That is deliberate — upgrading
 * keeps every setting, the 2FA state, the file baseline and the quarantine
 * without a migration step that could fail half-way on a live site.
 */

/**
 * Emergency escape hatch.
 *
 * If you are ever locked out by two-factor authentication (mail server down,
 * lost inbox access), add this line to wp-config.php, log in, fix the issue,
 * then REMOVE the line again:
 *
 *     define( 'EJABH_SEC_2FA_BYPASS', true );
 *
 * The old DYS_SEC_2FA_BYPASS constant is still honoured.
 */

require_once EJABH_SEC_DIR . 'includes/class-ejabh-settings.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-logger.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-findings.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-mailer.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-signatures.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-threat-detector.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-core-integrity.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-verifier.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-fim.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-file-scanner.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-db-scanner.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-integrity.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-2fa.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-sessions.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-plugin-guard.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-caps.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-user-guard.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-login-limiter.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-hardening.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-quarantine.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-upload-guard.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-watcher.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-scheduler.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-report.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-daily-report.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-updater.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-clean-admin.php';
require_once EJABH_SEC_DIR . 'includes/class-ejabh-plugin.php';

if ( is_admin() ) {
	require_once EJABH_SEC_DIR . 'admin/class-ejabh-admin.php';
}

/*
 * Inspect uploaded files now, while this file is being included — before
 * `plugins_loaded`, and so before any other plugin's code gets a chance to
 * move_uploaded_file() them somewhere executable. A vulnerable upload handler
 * elsewhere on the site then receives nothing to save.
 */
Ejabh_Upload_Guard::inspect_request();

/**
 * Boot the plugin.
 *
 * @return Ejabh_Plugin
 */
function ejabh_sec() {
	static $instance = null;
	if ( null === $instance ) {
		$instance = new Ejabh_Plugin();
	}
	return $instance;
}

ejabh_sec()->boot();

register_activation_hook( __FILE__, array( 'Ejabh_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Ejabh_Plugin', 'deactivate' ) );
