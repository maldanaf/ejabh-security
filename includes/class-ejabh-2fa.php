<?php
/**
 * Mandatory e-mail two-factor authentication.
 *
 * Flow
 * ----
 * 1. The user submits a correct username + password anywhere on the site.
 * 2. `wp_login` fires. We immediately drop the auth cookie WordPress just set
 *    (which also destroys the session token), stash a "pending login" record
 *    server-side, mail a one-time code, and redirect to our challenge screen.
 * 3. The challenge screen lives at `wp-login.php?action=dys_2fa`. The pending
 *    record is addressed by a random token held in an HttpOnly cookie, so the
 *    identity of the half-logged-in user never travels in a URL.
 * 4. A correct code re-issues the auth cookie and sends the user on their way.
 *
 * Bypass paths (XML-RPC, application passwords) are closed separately because
 * they authenticate without ever reaching an interactive screen.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Two-factor authentication over e-mail.
 */
class Ejabh_2FA {

	/** Cookie holding the pending-login token. */
	const COOKIE = 'dys_sec_pending';

	/** Transient key prefix for pending logins. */
	const PENDING_PREFIX = 'dys_sec_p_';

	/** login action slug for the challenge screen. */
	const ACTION = 'dys_2fa';

	/**
	 * Error message to show on the challenge screen.
	 *
	 * @var string
	 */
	private $error = '';

	/**
	 * Success notice to show on the challenge screen.
	 *
	 * @var string
	 */
	private $notice = '';

	/**
	 * Register hooks.
	 *
	 * @return void
	 */
	public function hooks() {
		if ( ! Ejabh_Settings::get( '2fa_enabled' ) ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'challenge' ), 5, 2 );
		add_action( 'login_form_' . self::ACTION, array( $this, 'handle_challenge_screen' ) );

		// Close the non-interactive authentication paths that would skip 2FA.
		if ( Ejabh_Settings::get( '2fa_block_xmlrpc' ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( $this, 'strip_xmlrpc_methods' ) );
		}
		if ( Ejabh_Settings::get( '2fa_block_app_pw' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
	}

	/**
	 * Whether the emergency bypass constant is active.
	 *
	 * @return bool
	 */
	public static function bypassed() {
		// The pre-rename constant is still honoured so existing runbooks keep working.
		return ( defined( 'EJABH_SEC_2FA_BYPASS' ) && EJABH_SEC_2FA_BYPASS )
			|| ( defined( 'DYS_SEC_2FA_BYPASS' ) && DYS_SEC_2FA_BYPASS );
	}

	/**
	 * Does this user have to pass a second factor?
	 *
	 * @param WP_User $user User being authenticated.
	 * @return bool
	 */
	public function user_requires_2fa( $user ) {
		if ( ! $user instanceof WP_User || ! $user->ID ) {
			return false;
		}
		if ( self::bypassed() ) {
			return false;
		}

		$exempt = (array) Ejabh_Settings::get( '2fa_exempt_user_ids' );
		if ( in_array( (int) $user->ID, array_map( 'intval', $exempt ), true ) ) {
			return false;
		}

		/**
		 * Filter whether a user must complete e-mail 2FA.
		 *
		 * @param bool    $required Whether 2FA is required.
		 * @param WP_User $user     The user.
		 */
		return (bool) apply_filters( 'dys_sec_user_requires_2fa', true, $user );
	}

	/**
	 * Intercept a successful password authentication.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       Authenticated user.
	 * @return void
	 */
	public function challenge( $user_login, $user = null ) {
		if ( ! $user instanceof WP_User ) {
			$user = get_user_by( 'login', $user_login );
		}
		if ( ! $this->user_requires_2fa( $user ) ) {
			return;
		}

		// Non-interactive contexts cannot show a challenge screen. Those paths are
		// blocked outright above; if one still gets here, refuse rather than let it
		// through unchallenged.
		if ( wp_doing_cron() || 'cli' === PHP_SAPI ) {
			return;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			wp_clear_auth_cookie();
			Ejabh_Logger::log( '2fa_blocked_xmlrpc', 'رُفض دخول عبر XML-RPC لأنه يتجاوز المصادقة الثنائية.', 'warning', $user->ID );
			return;
		}

		if ( ! $user->user_email || ! is_email( $user->user_email ) ) {
			// No way to deliver a code. Fail closed unless explicitly told otherwise.
			Ejabh_Logger::log(
				'2fa_no_email',
				sprintf( 'المستخدم %s (#%d) ليس لديه بريد صالح، فتعذّر إرسال رمز التحقق.', $user->user_login, $user->ID ),
				'critical',
				$user->ID
			);
			if ( ! Ejabh_Settings::get( '2fa_fail_open' ) ) {
				wp_clear_auth_cookie();
				wp_die(
					esc_html__( 'حسابك لا يحتوي على بريد إلكتروني صالح، ولا يمكن إتمام المصادقة الثنائية. راجع مسؤول الموقع.', 'ejabh-security' ),
					esc_html__( 'تعذّر تسجيل الدخول', 'ejabh-security' ),
					array( 'response' => 403 )
				);
			}
			return;
		}

		$context = array(
			'redirect_to' => isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'remember'    => ! empty( $_REQUEST['rememberme'] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'interim'     => isset( $_REQUEST['interim-login'] ), // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		// Undo the login WordPress just completed. This also destroys the freshly
		// created session token via the clear_auth_cookie hook.
		wp_clear_auth_cookie();

		$token = $this->start_pending( $user, $context );
		if ( ! $token ) {
			wp_die(
				esc_html__( 'تعذّر بدء عملية التحقق. أعد المحاولة.', 'ejabh-security' ),
				esc_html__( 'خطأ', 'ejabh-security' ),
				array( 'response' => 500 )
			);
		}

		$this->issue_code( $token, $user );

		Ejabh_Logger::log(
			'2fa_challenge_sent',
			sprintf( 'أُرسل رمز تحقق إلى %s للمستخدم %s (#%d).', $this->mask_email( $user->user_email ), $user->user_login, $user->ID ),
			'info',
			$user->ID
		);

		$url = add_query_arg( 'action', self::ACTION, wp_login_url() );
		if ( $context['interim'] ) {
			$url = add_query_arg( 'interim-login', '1', $url );
		}

		if ( headers_sent() ) {
			// Extremely unlikely, but never leave the user in limbo.
			printf(
				'<p>%s <a href="%s">%s</a></p>',
				esc_html__( 'أُرسل رمز التحقق إلى بريدك.', 'ejabh-security' ),
				esc_url( $url ),
				esc_html__( 'اضغط هنا لإدخال الرمز', 'ejabh-security' )
			);
			exit;
		}

		wp_safe_redirect( $url );
		exit;
	}

	/**
	 * Render or process the challenge screen at wp-login.php?action=dys_2fa.
	 *
	 * @return void
	 */
	public function handle_challenge_screen() {
		$token   = $this->cookie_token();
		$pending = $token ? $this->get_pending( $token ) : false;

		if ( ! $pending ) {
			$this->clear_cookie();
			wp_safe_redirect( add_query_arg( 'dys_expired', '1', wp_login_url() ) );
			exit;
		}

		$user = get_userdata( (int) $pending['user_id'] );
		if ( ! $user ) {
			$this->destroy_pending( $token );
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$is_post = isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' === strtoupper( wp_unslash( $_SERVER['REQUEST_METHOD'] ) );

		// The HttpOnly pending cookie is the primary CSRF defence here (an
		// attacker cannot read it). The nonce is a second, cheap barrier.
		if ( $is_post ) {
			$nonce = isset( $_POST['dys_2fa_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['dys_2fa_nonce'] ) ) : '';
			if ( ! wp_verify_nonce( $nonce, 'dys_sec_2fa_verify' ) ) {
				$this->error = __( 'انتهت صلاحية النموذج. أعد إدخال الرمز.', 'ejabh-security' );
				$this->render_form( $user, $pending );
				exit;
			}
		}

		if ( $is_post && isset( $_POST['dys_resend'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$this->handle_resend( $token, $pending, $user );
			$pending = $this->get_pending( $token );
		} elseif ( $is_post ) {
			$this->handle_verify( $token, $pending, $user );
			$pending = $this->get_pending( $token ); // Refresh attempt counter for the form.
			if ( ! $pending ) {
				// Pending record was destroyed (too many attempts).
				$this->clear_cookie();
				wp_safe_redirect( add_query_arg( 'dys_locked', '1', wp_login_url() ) );
				exit;
			}
		}

		$this->render_form( $user, $pending );
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Pending login record
	 * ------------------------------------------------------------------ */

	/**
	 * Create a pending-login record and set its cookie.
	 *
	 * @param WP_User $user    User awaiting a code.
	 * @param array   $context Login context to replay after success.
	 * @return string|false The token, or false on failure.
	 */
	private function start_pending( $user, array $context ) {
		$token = wp_generate_password( 43, false, false );
		$data  = array(
			'user_id'      => (int) $user->ID,
			'redirect_to'  => (string) $context['redirect_to'],
			'remember'     => (bool) $context['remember'],
			'interim'      => (bool) $context['interim'],
			'created'      => time(),
			'attempts'     => 0,
			'sends'        => 0,
			'last_sent'    => 0,
			'code_hash'    => '',
			'code_expires' => 0,
			'ip'           => Ejabh_Logger::client_ip(),
		);

		$ttl = 15 * MINUTE_IN_SECONDS;
		if ( ! set_transient( self::PENDING_PREFIX . $this->key( $token ), $data, $ttl ) ) {
			return false;
		}

		$this->set_cookie( $token, time() + $ttl );
		return $token;
	}

	/**
	 * Load a pending-login record.
	 *
	 * @param string $token Pending token.
	 * @return array|false
	 */
	private function get_pending( $token ) {
		$data = get_transient( self::PENDING_PREFIX . $this->key( $token ) );
		return is_array( $data ) && ! empty( $data['user_id'] ) ? $data : false;
	}

	/**
	 * Persist changes to a pending-login record.
	 *
	 * @param string $token Pending token.
	 * @param array  $data  Full record.
	 * @return void
	 */
	private function save_pending( $token, array $data ) {
		$remaining = 15 * MINUTE_IN_SECONDS - ( time() - (int) $data['created'] );
		if ( $remaining < 30 ) {
			$remaining = 30;
		}
		set_transient( self::PENDING_PREFIX . $this->key( $token ), $data, $remaining );
	}

	/**
	 * Delete a pending-login record and its cookie.
	 *
	 * @param string $token Pending token.
	 * @return void
	 */
	private function destroy_pending( $token ) {
		delete_transient( self::PENDING_PREFIX . $this->key( $token ) );
		$this->clear_cookie();
	}

	/**
	 * Transient key fragment for a token.
	 *
	 * @param string $token Pending token.
	 * @return string
	 */
	private function key( $token ) {
		return substr( hash( 'sha256', $token ), 0, 40 );
	}

	/* ---------------------------------------------------------------------
	 * Codes
	 * ------------------------------------------------------------------ */

	/**
	 * Generate, store and mail a fresh code.
	 *
	 * @param string  $token Pending token.
	 * @param WP_User $user  Target user.
	 * @return bool Whether the mail was accepted.
	 */
	private function issue_code( $token, $user ) {
		$pending = $this->get_pending( $token );
		if ( ! $pending ) {
			return false;
		}

		if ( $this->ip_send_limit_reached() ) {
			Ejabh_Logger::log(
				'2fa_send_throttled',
				sprintf( 'تم تجاوز حد إرسال الرموز من العنوان %s.', Ejabh_Logger::client_ip() ),
				'warning',
				$user->ID
			);

			$this->error = __( 'تم تجاوز عدد محاولات الإرسال المسموح. انتظر قليلاً ثم أعد المحاولة.', 'ejabh-security' );

			// The challenge screen is reached via a redirect, so the message has
			// to survive in the pending record rather than on this instance.
			$pending['flash_error'] = $this->error;
			$this->save_pending( $token, $pending );

			return false;
		}

		$length = max( 4, min( 10, (int) Ejabh_Settings::get( '2fa_code_length' ) ) );
		$code   = $this->random_digits( $length );

		$pending['code_hash']    = wp_hash_password( $code );
		$pending['code_expires'] = time() + (int) Ejabh_Settings::get( '2fa_code_ttl' );
		$pending['last_sent']    = time();
		$pending['sends']        = (int) $pending['sends'] + 1;
		$pending['attempts']     = 0; // A new code resets the attempt counter.
		$this->save_pending( $token, $pending );

		$this->bump_ip_send_counter();

		$sent = Ejabh_Mailer::send_login_code( $user, $code );

		if ( ! $sent ) {
			Ejabh_Logger::log(
				'2fa_mail_failed',
				sprintf( 'فشل إرسال رمز التحقق للمستخدم %s (#%d). راجع إعدادات البريد على السيرفر.', $user->user_login, $user->ID ),
				'critical',
				$user->ID
			);

			if ( Ejabh_Settings::get( '2fa_fail_open' ) ) {
				// Explicitly configured to prefer availability over strictness.
				$this->destroy_pending( $token );
				$this->complete_login( $user, $pending );
			}
		}

		return (bool) $sent;
	}

	/**
	 * Cryptographically random numeric string.
	 *
	 * @param int $length Number of digits.
	 * @return string
	 */
	private function random_digits( $length ) {
		$out = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$out .= (string) random_int( 0, 9 );
		}
		return $out;
	}

	/**
	 * Verify a submitted code.
	 *
	 * @param string  $token   Pending token.
	 * @param array   $pending Pending record.
	 * @param WP_User $user    User awaiting verification.
	 * @return void
	 */
	private function handle_verify( $token, array $pending, $user ) {
		$submitted = isset( $_POST['dys_code'] ) ? preg_replace( '/\D/', '', wp_unslash( $_POST['dys_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( '' === $submitted ) {
			$this->error = __( 'أدخل رمز التحقق.', 'ejabh-security' );
			return;
		}

		if ( empty( $pending['code_hash'] ) || time() > (int) $pending['code_expires'] ) {
			$this->error = __( 'انتهت صلاحية الرمز. اطلب رمزاً جديداً.', 'ejabh-security' );
			return;
		}

		$max = max( 1, (int) Ejabh_Settings::get( '2fa_max_attempts' ) );

		if ( ! wp_check_password( $submitted, $pending['code_hash'] ) ) {
			$pending['attempts'] = (int) $pending['attempts'] + 1;

			if ( $pending['attempts'] >= $max ) {
				Ejabh_Logger::log(
					'2fa_lockout',
					sprintf( 'أُلغيت محاولة دخول المستخدم %s (#%d) بعد %d رموز خاطئة من العنوان %s.', $user->user_login, $user->ID, $pending['attempts'], Ejabh_Logger::client_ip() ),
					'critical',
					$user->ID
				);
				Ejabh_Mailer::send_lockout_notice( $user );
				$this->destroy_pending( $token );
				return;
			}

			$this->save_pending( $token, $pending );
			Ejabh_Logger::log(
				'2fa_bad_code',
				sprintf( 'رمز خاطئ للمستخدم %s (#%d) — المحاولة %d من %d.', $user->user_login, $user->ID, $pending['attempts'], $max ),
				'warning',
				$user->ID
			);

			/**
			 * Fires when a submitted second factor is wrong.
			 *
			 * The login rate limiter counts this like any other failed
			 * authentication, so guessing codes gets the IP blocked too.
			 *
			 * @param WP_User $user The user.
			 */
			do_action( 'dys_sec_2fa_failed', $user );

			$this->error = sprintf(
				/* translators: %d: number of attempts left. */
				__( 'الرمز غير صحيح. بقي لك %d محاولة.', 'ejabh-security' ),
				max( 0, $max - (int) $pending['attempts'] )
			);
			return;
		}

		// Correct code.
		$this->destroy_pending( $token );
		Ejabh_Logger::log(
			'2fa_success',
			sprintf( 'أكمل المستخدم %s (#%d) المصادقة الثنائية بنجاح.', $user->user_login, $user->ID ),
			'info',
			$user->ID
		);
		$this->complete_login( $user, $pending );
	}

	/**
	 * Re-send a code, subject to a cooldown.
	 *
	 * @param string  $token   Pending token.
	 * @param array   $pending Pending record.
	 * @param WP_User $user    Target user.
	 * @return void
	 */
	private function handle_resend( $token, array $pending, $user ) {
		$wait = max( 15, (int) Ejabh_Settings::get( '2fa_resend_wait' ) );
		$age  = time() - (int) $pending['last_sent'];

		if ( $age < $wait ) {
			$this->error = sprintf(
				/* translators: %d: seconds to wait. */
				__( 'انتظر %d ثانية قبل طلب رمز جديد.', 'ejabh-security' ),
				$wait - $age
			);
			return;
		}

		if ( $this->issue_code( $token, $user ) ) {
			$this->notice = __( 'تم إرسال رمز جديد إلى بريدك.', 'ejabh-security' );
		} elseif ( ! $this->error ) {
			$this->error = __( 'تعذّر إرسال الرمز. راجع مسؤول الموقع.', 'ejabh-security' );
		}
	}

	/**
	 * Issue the real auth cookie and send the user where they were going.
	 *
	 * @param WP_User $user    Verified user.
	 * @param array   $pending Pending record (for redirect context).
	 * @return void
	 */
	private function complete_login( $user, array $pending ) {
		wp_set_auth_cookie( $user->ID, ! empty( $pending['remember'] ) );
		wp_set_current_user( $user->ID );

		/**
		 * Fires after a user clears the second factor.
		 *
		 * @param WP_User $user The user.
		 */
		do_action( 'dys_sec_2fa_passed', $user );

		if ( ! empty( $pending['interim'] ) ) {
			$this->render_interim_success();
			exit;
		}

		$requested = (string) $pending['redirect_to'];
		$redirect  = $requested ? $requested : admin_url();

		if ( ! $user->has_cap( 'edit_posts' ) && ( ! $requested || admin_url() === $requested ) ) {
			$redirect = $user->has_cap( 'read' ) ? admin_url( 'profile.php' ) : home_url();
		}

		/** This filter is documented in wp-login.php */
		$redirect = apply_filters( 'login_redirect', $redirect, $requested, $user );

		wp_safe_redirect( $redirect );
		exit;
	}

	/* ---------------------------------------------------------------------
	 * Throttling
	 * ------------------------------------------------------------------ */

	/**
	 * Transient key for the per-IP send counter.
	 *
	 * @return string
	 */
	private function ip_counter_key() {
		return 'dys_sec_sends_' . md5( Ejabh_Logger::client_ip() );
	}

	/**
	 * Has this IP asked for too many codes recently?
	 *
	 * @return bool
	 */
	private function ip_send_limit_reached() {
		return (int) get_transient( $this->ip_counter_key() ) >= 12;
	}

	/**
	 * Increment the per-IP send counter.
	 *
	 * @return void
	 */
	private function bump_ip_send_counter() {
		$key = $this->ip_counter_key();
		$n   = (int) get_transient( $key );
		set_transient( $key, $n + 1, 10 * MINUTE_IN_SECONDS );
	}

	/* ---------------------------------------------------------------------
	 * Cookie helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Set the pending-login cookie.
	 *
	 * @param string $token   Pending token.
	 * @param int    $expires Unix expiry.
	 * @return void
	 */
	private function set_cookie( $token, $expires ) {
		$secure = is_ssl();
		$path   = defined( 'SITECOOKIEPATH' ) && SITECOOKIEPATH ? SITECOOKIEPATH : '/';
		$domain = defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '';

		setcookie(
			self::COOKIE,
			$token,
			array(
				'expires'  => $expires,
				'path'     => $path,
				'domain'   => $domain,
				'secure'   => $secure,
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		$_COOKIE[ self::COOKIE ] = $token;
	}

	/**
	 * Remove the pending-login cookie.
	 *
	 * @return void
	 */
	private function clear_cookie() {
		$path   = defined( 'SITECOOKIEPATH' ) && SITECOOKIEPATH ? SITECOOKIEPATH : '/';
		$domain = defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '';

		if ( ! headers_sent() ) {
			setcookie(
				self::COOKIE,
				'',
				array(
					'expires'  => time() - 3600,
					'path'     => $path,
					'domain'   => $domain,
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
		unset( $_COOKIE[ self::COOKIE ] );
	}

	/**
	 * Read and sanitise the pending token from the cookie.
	 *
	 * @return string
	 */
	private function cookie_token() {
		if ( empty( $_COOKIE[ self::COOKIE ] ) ) {
			return '';
		}
		$token = preg_replace( '/[^A-Za-z0-9]/', '', wp_unslash( $_COOKIE[ self::COOKIE ] ) );
		return strlen( $token ) === 43 ? $token : '';
	}

	/* ---------------------------------------------------------------------
	 * Rendering
	 * ------------------------------------------------------------------ */

	/**
	 * Output the code-entry screen using the native login chrome.
	 *
	 * @param WP_User $user    User awaiting verification.
	 * @param array   $pending Pending record.
	 * @return void
	 */
	private function render_form( $user, array $pending ) {
		global $interim_login;

		$interim_login = ! empty( $pending['interim'] ) ? true : $interim_login; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		// Pick up a message carried across the redirect, then clear it so it is
		// shown exactly once.
		if ( ! $this->error && ! empty( $pending['flash_error'] ) ) {
			$this->error = (string) $pending['flash_error'];
			$token       = $this->cookie_token();
			if ( $token ) {
				unset( $pending['flash_error'] );
				$this->save_pending( $token, $pending );
			}
		}

		$message = '<p class="message">' . sprintf(
			/* translators: %s: masked e-mail address. */
			esc_html__( 'أرسلنا رمز تحقق إلى %s. أدخله للمتابعة.', 'ejabh-security' ),
			'<strong>' . esc_html( $this->mask_email( $user->user_email ) ) . '</strong>'
		) . '</p>';

		if ( $this->notice ) {
			$message .= '<p class="message">' . esc_html( $this->notice ) . '</p>';
		}

		$wp_error = null;
		if ( $this->error ) {
			$wp_error = new WP_Error( 'dys_2fa', $this->error );
		}

		login_header( __( 'التحقق بخطوتين', 'ejabh-security' ), $message, $wp_error );

		$action_url = add_query_arg( 'action', self::ACTION, wp_login_url() );
		$length     = max( 4, min( 10, (int) Ejabh_Settings::get( '2fa_code_length' ) ) );
		$expires_in = max( 0, (int) $pending['code_expires'] - time() );
		?>
		<form name="dys_2fa_form" id="dys_2fa_form" action="<?php echo esc_url( $action_url ); ?>" method="post" autocomplete="off">
			<?php wp_nonce_field( 'dys_sec_2fa_verify', 'dys_2fa_nonce' ); ?>
			<?php if ( ! empty( $pending['interim'] ) ) : ?>
				<input type="hidden" name="interim-login" value="1" />
			<?php endif; ?>

			<p>
				<label for="dys_code"><?php esc_html_e( 'رمز التحقق', 'ejabh-security' ); ?></label>
				<input type="text"
					name="dys_code"
					id="dys_code"
					class="input"
					value=""
					size="20"
					inputmode="numeric"
					pattern="[0-9]*"
					maxlength="<?php echo esc_attr( $length ); ?>"
					autocomplete="one-time-code"
					dir="ltr"
					style="text-align:center;letter-spacing:.5em;font-size:1.4em;"
					autofocus />
			</p>

			<p class="description" style="margin-bottom:16px;">
				<?php
				printf(
					/* translators: %d: seconds remaining. */
					esc_html__( 'صلاحية الرمز تنتهي بعد %d ثانية.', 'ejabh-security' ),
					(int) $expires_in
				);
				?>
			</p>

			<p class="submit">
				<input type="submit" name="dys_submit" id="dys_submit" class="button button-primary button-large"
					value="<?php esc_attr_e( 'تحقق وسجّل الدخول', 'ejabh-security' ); ?>" style="width:100%;" />
			</p>
		</form>

		<form name="dys_2fa_resend" action="<?php echo esc_url( $action_url ); ?>" method="post" style="margin-top:12px;">
			<?php wp_nonce_field( 'dys_sec_2fa_verify', 'dys_2fa_nonce' ); ?>
			<input type="hidden" name="dys_resend" value="1" />
			<button type="submit" class="button button-secondary" style="width:100%;">
				<?php esc_html_e( 'إرسال رمز جديد', 'ejabh-security' ); ?>
			</button>
		</form>

		<p id="nav" style="margin-top:16px;">
			<a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( '← الرجوع إلى صفحة الدخول', 'ejabh-security' ); ?></a>
		</p>
		<?php
		login_footer( 'dys_code' );
	}

	/**
	 * Mirror the core "logged in successfully" interim-login screen.
	 *
	 * @return void
	 */
	private function render_interim_success() {
		global $interim_login;
		$interim_login = 'success'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		$message = '<p class="message">' . esc_html__( 'تم تسجيل الدخول بنجاح.', 'ejabh-security' ) . '</p>';
		login_header( '', $message );
		echo '</div>';

		/** This action is documented in wp-login.php */
		do_action( 'login_footer' );

		echo '</body></html>';
	}

	/* ---------------------------------------------------------------------
	 * Misc
	 * ------------------------------------------------------------------ */

	/**
	 * Partially hide an e-mail address for display.
	 *
	 * @param string $email Address.
	 * @return string
	 */
	public function mask_email( $email ) {
		if ( ! $email || false === strpos( $email, '@' ) ) {
			return '';
		}
		list( $local, $domain ) = explode( '@', $email, 2 );
		$len                    = strlen( $local );

		if ( $len <= 2 ) {
			$masked = str_repeat( '•', $len );
		} else {
			$masked = substr( $local, 0, 2 ) . str_repeat( '•', max( 2, $len - 3 ) ) . substr( $local, -1 );
		}

		return $masked . '@' . $domain;
	}

	/**
	 * Remove the XML-RPC methods that authenticate or amplify attacks.
	 *
	 * @param array $methods Registered methods.
	 * @return array
	 */
	public function strip_xmlrpc_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'], $methods['system.multicall'] );
		return $methods;
	}
}
