<?php
/**
 * Authenticity oracle.
 *
 * Signature scanning is guesswork: it looks for code that *resembles* malware.
 * A cryptographic checksum is proof. If a file is byte-identical to what
 * WordPress.org publishes, it is authentic by definition — no pattern match on
 * it can be anything but a false positive.
 *
 * WordPress core genuinely contains `eval()`, `base64_decode()`, `wp_create_user()`
 * and the literal string `wp-feed.php`. Scanning verified files for those
 * produced a wall of "critical" findings on untouched core code, which is worse
 * than useless: it buries the real ones and trains people to ignore the report.
 *
 * So: verify first, and only hand the scanner what could not be proven.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Decides whether a file matches an official published release.
 */
class Ejabh_Verifier {

	/**
	 * Core checksum map, or null before it is loaded.
	 *
	 * @var array|null
	 */
	private $core = null;

	/**
	 * Cached plugin manifests, keyed by slug.
	 *
	 * @var array
	 */
	private $plugins = array();

	/**
	 * Installed plugin versions, keyed by slug.
	 *
	 * @var array|null
	 */
	private $versions = null;

	/**
	 * Files proven authentic during this scan.
	 *
	 * @var int
	 */
	public $verified = 0;

	/**
	 * Load the reference data once per scan.
	 *
	 * @return void
	 */
	public function prepare() {
		if ( null !== $this->core ) {
			return;
		}

		$core       = Ejabh_Core_Integrity::checksums();
		$this->core = is_wp_error( $core ) ? array() : $core;

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$this->versions = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( false === strpos( $file, '/' ) ) {
				continue;
			}
			$this->versions[ strtok( $file, '/' ) ] = (string) $data['Version'];
		}
	}

	/**
	 * Is the reference data usable at all?
	 *
	 * When core checksums could not be fetched we must not skip anything, or an
	 * offline server would silently scan nothing.
	 *
	 * @return bool
	 */
	public function has_reference() {
		return ! empty( $this->core );
	}

	/**
	 * Is this file byte-identical to an official release?
	 *
	 * @param string $rel      Site-relative path.
	 * @param string $contents File contents.
	 * @return bool
	 */
	public function is_authentic( $rel, $contents ) {
		$expected = $this->expected_hash( $rel );

		if ( null === $expected ) {
			return false;
		}

		if ( hash_equals( $expected, md5( $contents ) ) ) {
			++$this->verified;
			return true;
		}

		// A checkout edited on Windows differs only by line endings.
		if ( hash_equals( $expected, md5( str_replace( "\r\n", "\n", $contents ) ) ) ) {
			++$this->verified;
			return true;
		}

		return false;
	}

	/**
	 * The official MD5 for a path, if any reference knows it.
	 *
	 * @param string $rel Site-relative path.
	 * @return string|null
	 */
	private function expected_hash( $rel ) {
		// Core ships everything outside wp-content, plus its bundled plugins
		// and default themes.
		if ( isset( $this->core[ $rel ] ) ) {
			return (string) $this->core[ $rel ];
		}

		if ( 0 !== strpos( $rel, 'wp-content/plugins/' ) ) {
			return null;
		}

		$rest = substr( $rel, strlen( 'wp-content/plugins/' ) );
		$slug = strtok( $rest, '/' );

		if ( ! $slug || false === strpos( $rest, '/' ) ) {
			return null;
		}

		$manifest = $this->plugin_manifest( $slug );
		if ( ! $manifest ) {
			return null;
		}

		$inner = substr( $rest, strlen( $slug ) + 1 );

		return isset( $manifest[ $inner ]['md5'] ) ? (string) $manifest[ $inner ]['md5'] : null;
	}

	/**
	 * Cached-only manifest lookup for a plugin.
	 *
	 * Deliberately never hits the network: a file scan walks tens of thousands
	 * of paths and must not turn into an HTTP storm. The integrity audit is what
	 * populates this cache, so running it first makes the file scan quieter.
	 *
	 * @param string $slug Plugin slug.
	 * @return array Empty when unknown.
	 */
	private function plugin_manifest( $slug ) {
		if ( isset( $this->plugins[ $slug ] ) ) {
			return $this->plugins[ $slug ];
		}

		$this->plugins[ $slug ] = array();

		$version = isset( $this->versions[ $slug ] ) ? $this->versions[ $slug ] : '';
		if ( ! $version ) {
			return $this->plugins[ $slug ];
		}

		$cached = get_transient( 'dys_sec_cksum_' . md5( $slug . '|' . $version ) );

		if ( is_array( $cached ) ) {
			$this->plugins[ $slug ] = $cached;
		}

		return $this->plugins[ $slug ];
	}
}
