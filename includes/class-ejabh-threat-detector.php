<?php
/**
 * Shared content verdicts.
 *
 * The full file scan, the upload guard and the new-file watcher all need the
 * same answer to "is this file malicious?". Keeping that answer in one place
 * means a rule added for one of them protects all three.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Runs the signature set over a blob and says whether it is safe to act on.
 */
class Ejabh_Threat_Detector {

	/** Extensions the web server will execute as PHP. */
	const PHP_EXT = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phar', 'phps', 'inc', 'module' );

	/** Extensions a browser renders as a page — where phishing lives. */
	const MARKUP_EXT = array( 'html', 'htm', 'shtml', 'xhtml', 'svg' );

	/**
	 * Rules precise enough to act on with nobody watching.
	 *
	 * The upload guard and the watcher delete or quarantine on these alone, so
	 * each one must describe something no legitimate file does. Broad
	 * indicators (eval(), base64_decode(), unauthenticated uploads) stay
	 * report-only and wait for a human.
	 *
	 * @return array Rule IDs.
	 */
	public static function blocking_rules() {
		return array(
			// Backdoors.
			'eval_on_decoder',
			'exec_on_superglobal',
			'callable_superglobal',
			'call_user_func_superglobal',
			'eval_php_input',
			'password_gated_shell',
			'write_from_request',
			'known_shell_marker',
			'wpvcd_marker',
			'combo_shell_toolkit',
			// Uploader shells.
			'uploader_request_destination',
			'uploader_shell_marker',
			'combo_standalone_uploader',
			'combo_recon_uploader',
			// Phishing.
			'telegram_exfiltration',
			'phish_vendor_assets',
			'phish_document_lure',
			'phish_offsite_password_form',
			'phish_brand_login',
		);
	}

	/**
	 * Lower-case extension of a path or file name.
	 *
	 * @param string $name Path or file name.
	 * @return string
	 */
	public static function ext( $name ) {
		return strtolower( (string) pathinfo( (string) $name, PATHINFO_EXTENSION ) );
	}

	/**
	 * Whether a name will be executed as PHP — including "x.php.jpg" tricks
	 * that some Apache configurations still run.
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	public static function is_executable_name( $name ) {
		$name = strtolower( basename( (string) $name ) );

		if ( in_array( self::ext( $name ), self::PHP_EXT, true ) ) {
			return true;
		}

		return (bool) preg_match( '/\.(?:php[3-8]?|phtml|pht|phar)\./', $name );
	}

	/**
	 * Does this blob contain PHP code at all?
	 *
	 * @param string $contents Data.
	 * @return bool
	 */
	public static function has_php( $contents ) {
		return false !== stripos( $contents, '<?php' ) || false !== strpos( $contents, '<?=' );
	}

	/**
	 * Should the phishing rules run on this file?
	 *
	 * Markup everywhere outside core. PHP only where a plugin or theme would not
	 * legitimately render a branded password field (a PayPal API password
	 * setting in a donation plugin is not phishing).
	 *
	 * @param string $rel Site-relative path, or a bare file name for uploads.
	 * @return bool
	 */
	public static function phishing_applies( $rel ) {
		$rel = ltrim( str_replace( '\\', '/', (string) $rel ), '/' );

		// Core, translations (which legitimately say "Document", "PayPal",
		// "Sign in"…) and page caches (copies of the site's own pages).
		foreach ( array( 'wp-admin/', 'wp-includes/', 'wp-content/languages/', 'wp-content/cache/' ) as $prefix ) {
			if ( 0 === strpos( $rel, $prefix ) ) {
				return false;
			}
		}

		$ext = self::ext( $rel );

		if ( in_array( $ext, self::MARKUP_EXT, true ) ) {
			return true;
		}

		if ( in_array( $ext, self::PHP_EXT, true ) ) {
			return 0 !== strpos( $rel, 'wp-content/plugins/' )
				&& 0 !== strpos( $rel, 'wp-content/themes/' )
				&& 0 !== strpos( $rel, 'wp-content/mu-plugins/' );
		}

		return false;
	}

	/**
	 * Every rule that matches.
	 *
	 * @param string $contents File contents.
	 * @param string $rel      Site-relative path (or upload file name).
	 * @return array List of {id, severity, title, offset}.
	 */
	public static function examine( $contents, $rel ) {
		$hits = array();

		// Code rules only mean something where there is code.
		$code = self::has_php( $contents ) || in_array( self::ext( $rel ), self::PHP_EXT, true );

		if ( $code ) {
			foreach ( Ejabh_Signatures::patterns() as $rule ) {
				if ( preg_match( $rule['regex'], $contents, $m, PREG_OFFSET_CAPTURE ) ) {
					$hits[] = self::hit( $rule, isset( $m[0][1] ) ? (int) $m[0][1] : 0 );
				}
			}
			foreach ( Ejabh_Signatures::combos() as $rule ) {
				$offset = self::combo_offset( $rule, $contents );
				if ( null !== $offset ) {
					$hits[] = self::hit( $rule, $offset );
				}
			}
		} else {
			// Exfiltration endpoints show up in JS and HTML too.
			foreach ( Ejabh_Signatures::patterns() as $rule ) {
				if ( 'telegram_exfiltration' === $rule['id'] && preg_match( $rule['regex'], $contents, $m, PREG_OFFSET_CAPTURE ) ) {
					$hits[] = self::hit( $rule, (int) $m[0][1] );
				}
			}
		}

		if ( self::phishing_applies( $rel ) && self::looks_like_page( $contents, $rel ) ) {
			foreach ( Ejabh_Signatures::phishing() as $rule ) {
				$offset = self::combo_offset( $rule, $contents );
				if ( null === $offset ) {
					continue;
				}
				// A form that posts back to this site is the site's own form.
				if ( 'phish_offsite_password_form' === $rule['id'] && ! self::posts_offsite( $contents ) ) {
					continue;
				}
				$hits[] = self::hit( $rule, $offset );
			}
		}

		return $hits;
	}

	/**
	 * Is this a rendered page rather than code that merely mentions brands?
	 *
	 * Markup files always are. A PHP file only counts when it emits HTML of its
	 * own — a translation table or a class file does not.
	 *
	 * @param string $contents File contents.
	 * @param string $rel      Path or name.
	 * @return bool
	 */
	private static function looks_like_page( $contents, $rel ) {
		if ( in_array( self::ext( $rel ), self::MARKUP_EXT, true ) ) {
			return true;
		}
		return (bool) preg_match( '/<(?:html|body|form|table|div|img)\b/i', $contents );
	}

	/**
	 * Does any form post to a host other than this site's?
	 *
	 * @param string $contents Markup.
	 * @return bool
	 */
	private static function posts_offsite( $contents ) {
		if ( ! preg_match_all( '/<form\b[^>]*action\s*=\s*[\'"]https?:\/\/([^\/\'":?#]+)/i', $contents, $m ) ) {
			return false;
		}

		$own = array();
		foreach ( array( function_exists( 'home_url' ) ? home_url() : '', function_exists( 'site_url' ) ? site_url() : '' ) as $url ) {
			$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			if ( $host ) {
				$own[] = preg_replace( '/^www\./', '', $host );
			}
		}

		foreach ( $m[1] as $host ) {
			if ( ! in_array( preg_replace( '/^www\./', '', strtolower( $host ) ), $own, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The first hit precise enough to act on unattended, if any.
	 *
	 * @param array $hits Output of examine().
	 * @return array|null
	 */
	public static function blocking_hit( array $hits ) {
		$blocking = self::blocking_rules();
		foreach ( $hits as $hit ) {
			if ( in_array( $hit['id'], $blocking, true ) ) {
				return $hit;
			}
		}
		return null;
	}

	/**
	 * Where a multi-regex rule matched, or null when it did not.
	 *
	 * @param array  $rule     Rule with `all` and optional `none`.
	 * @param string $contents Data.
	 * @return int|null Offset of the first regex's match.
	 */
	public static function combo_offset( array $rule, $contents ) {
		$first = null;

		foreach ( $rule['all'] as $regex ) {
			if ( ! preg_match( $regex, $contents, $m, PREG_OFFSET_CAPTURE ) ) {
				return null;
			}
			if ( null === $first ) {
				$first = isset( $m[0][1] ) ? (int) $m[0][1] : 0;
			}
		}

		if ( ! empty( $rule['none'] ) ) {
			foreach ( $rule['none'] as $regex ) {
				if ( preg_match( $regex, $contents ) ) {
					return null;
				}
			}
		}

		return (int) $first;
	}

	/**
	 * Normalise a rule into a hit record.
	 *
	 * @param array $rule   Rule definition.
	 * @param int   $offset Match offset.
	 * @return array
	 */
	private static function hit( array $rule, $offset ) {
		return array(
			'id'       => $rule['id'],
			'severity' => $rule['severity'],
			'title'    => $rule['title'],
			'offset'   => (int) $offset,
		);
	}
}
