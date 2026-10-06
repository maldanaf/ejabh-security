<?php
/**
 * Admin notice cleanup.
 *
 * Not a security control — a usability one. A site with two dozen plugins
 * accumulates upgrade nags, review requests and Black Friday banners until the
 * top of every admin page is several screens of scrolling. The practical harm
 * is that a genuine warning gets lost in the noise.
 *
 * Notices are captured rather than destroyed: they are buffered, counted, and
 * folded into one collapsible panel that can be opened on demand. Nothing is
 * lost, and a real message is still one click away.
 *
 * Our own notices and WordPress's own critical ones are always left visible.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Collapses third-party admin notices into a single panel.
 */
class Ejabh_Clean_Admin {

	/**
	 * Hook names that render notices.
	 */
	const NOTICE_HOOKS = array( 'admin_notices', 'all_admin_notices', 'network_admin_notices', 'user_admin_notices' );

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Ejabh_Settings::get( 'clean_admin_enabled' ) ) {
			return;
		}

		// Priority 0 opens the buffer before any plugin prints; PHP_INT_MAX
		// closes it after the last one.
		foreach ( self::NOTICE_HOOKS as $hook ) {
			add_action( $hook, array( $this, 'open_buffer' ), -PHP_INT_MAX );
			add_action( $hook, array( $this, 'close_buffer' ), PHP_INT_MAX );
		}

		add_action( 'admin_head', array( $this, 'styles' ) );
	}

	/**
	 * Should notices be left alone on this screen?
	 *
	 * @return bool
	 */
	private function should_skip() {
		// Never interfere on screens where a notice is the whole point.
		global $pagenow;

		$always_show = array( 'update-core.php', 'plugins.php', 'themes.php', 'update.php', 'site-health.php' );

		if ( in_array( (string) $pagenow, $always_show, true ) ) {
			return true;
		}

		// Our own screens already present their own messaging.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 0 === strpos( $page, 'ejabh-security' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Start capturing notice output.
	 *
	 * @return void
	 */
	public function open_buffer() {
		if ( $this->should_skip() ) {
			return;
		}
		ob_start();
	}

	/**
	 * Stop capturing, then re-emit what matters and fold away the rest.
	 *
	 * @return void
	 */
	public function close_buffer() {
		if ( $this->should_skip() ) {
			return;
		}
		if ( ! ob_get_level() ) {
			return;
		}

		$html = (string) ob_get_clean();

		if ( '' === trim( $html ) ) {
			return;
		}

		$keep = array();
		$hide = array();

		foreach ( $this->split_notices( $html ) as $notice ) {
			if ( $this->must_stay_visible( $notice ) ) {
				$keep[] = $notice;
			} else {
				$hide[] = $notice;
			}
		}

		echo implode( '', $keep ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pass-through of markup produced by other plugins.

		if ( ! $hide ) {
			return;
		}

		$count = count( $hide );
		?>
		<div class="notice notice-info ejabh-notice-fold">
			<p>
				<span class="dashicons dashicons-shield-alt"></span>
				<?php
				printf(
					/* translators: %d: number of hidden notices. */
					esc_html( _n( 'أُخفي %d إشعار من الإضافات لتنظيف الشاشة.', 'أُخفيت %d إشعارات من الإضافات لتنظيف الشاشة.', $count, 'ejabh-security' ) ),
					(int) $count
				);
				?>
				<button type="button" class="button-link ejabh-notice-toggle" aria-expanded="false"><?php esc_html_e( 'إظهارها', 'ejabh-security' ); ?></button>
			</p>
			<div class="ejabh-notice-hidden" hidden>
				<?php echo implode( '', $hide ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pass-through of markup produced by other plugins. ?>
			</div>
		</div>
		<script>
		( function () {
			var box = document.currentScript.closest( '.ejabh-notice-fold' );
			if ( ! box ) { return; }
			var btn = box.querySelector( '.ejabh-notice-toggle' );
			var panel = box.querySelector( '.ejabh-notice-hidden' );
			btn.addEventListener( 'click', function () {
				var open = ! panel.hidden;
				panel.hidden = open;
				btn.setAttribute( 'aria-expanded', open ? 'false' : 'true' );
				btn.textContent = open ? <?php echo wp_json_encode( __( 'إظهارها', 'ejabh-security' ) ); ?> : <?php echo wp_json_encode( __( 'إخفاؤها', 'ejabh-security' ) ); ?>;
			} );
		} )();
		</script>
		<?php
	}

	/**
	 * Split a blob of notice markup into individual top-level elements.
	 *
	 * @param string $html Captured output.
	 * @return array
	 */
	private function split_notices( $html ) {
		// Each notice is a top-level element; splitting on the boundary between
		// a closing tag and the next opening div keeps them intact.
		$parts = preg_split( '#(?<=>)\s*(?=<div\b|<p\b\s+class=["\'][^"\']*notice)#i', $html );

		$parts = array_values( array_filter( (array) $parts, static function ( $p ) {
			return '' !== trim( (string) $p );
		} ) );

		return $parts ? $parts : array( $html );
	}

	/**
	 * Is this notice too important to fold away?
	 *
	 * @param string $notice Notice markup.
	 * @return bool
	 */
	private function must_stay_visible( $notice ) {
		// Anything this plugin emitted.
		if ( false !== stripos( $notice, 'ejabh-sec' ) || false !== stripos( $notice, 'ejabh-' ) ) {
			return true;
		}

		// Errors and WordPress's own core messaging.
		$keep_markers = array(
			'notice-error',
			'error settings-error',
			'update-nag',
			'php-update-nag',
			'notice-warning is-dismissible update-message',
			'wp-die',
		);

		foreach ( $keep_markers as $marker ) {
			if ( false !== stripos( $notice, $marker ) ) {
				return true;
			}
		}

		// Anything reporting the result of an action the user just took.
		if ( false !== stripos( $notice, 'settings-error' ) || false !== stripos( $notice, 'notice-success' ) ) {
			return true;
		}

		/**
		 * Filter whether a notice survives the cleanup.
		 *
		 * @param bool   $keep   Whether to keep it visible.
		 * @param string $notice The notice markup.
		 */
		return (bool) apply_filters( 'dys_sec_keep_notice', false, $notice );
	}

	/**
	 * Minimal styling for the fold.
	 *
	 * @return void
	 */
	public function styles() {
		if ( $this->should_skip() ) {
			return;
		}
		?>
		<style>
			.ejabh-notice-fold .dashicons { color: #2271b1; vertical-align: text-bottom; }
			.ejabh-notice-fold .ejabh-notice-toggle { margin-inline-start: 8px; }
			.ejabh-notice-hidden { margin-top: 8px; border-top: 1px solid #dcdcde; padding-top: 8px; }
			.ejabh-notice-hidden .notice { margin-inline: 0; }
		</style>
		<?php
	}
}
