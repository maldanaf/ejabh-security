<?php
/**
 * Full-host file scanner.
 *
 * The scan is deliberately incremental. A WordPress install of this size has
 * tens of thousands of files, so a single request would time out. Instead the
 * scanner keeps a stack of directories still to visit in an option and walks it
 * for a few seconds per AJAX call, which the admin screen drives in a loop.
 *
 * @package Ejabh_Security
 */

defined( 'ABSPATH' ) || exit;

/**
 * Signature-based file scanner with core checksum verification.
 */
class Ejabh_File_Scanner {

	const STATE_OPTION = 'dys_sec_file_scan_state';

	/** Extensions that always get the full signature pass. */
	const PHP_EXT = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'pht', 'phar', 'phps', 'inc', 'module' );

	/** Text formats worth checking for smuggled PHP. */
	const TEXT_EXT = array( 'js', 'mjs', 'html', 'htm', 'xhtml', 'shtml', 'css', 'json', 'xml', 'svg', 'txt', 'md', 'ini', 'yml', 'yaml', 'htaccess', 'twig', 'tpl' );

	/** Largest non-PHP file we will open just to look for a PHP marker. */
	const MARKER_MAX_BYTES = 2097152;

	/**
	 * Fresh state array.
	 *
	 * @return array
	 */
	public static function blank_state() {
		return array(
			'scan_id'    => '',
			'status'     => 'idle',
			'stack'      => array(),
			'scanned'    => 0,
			'flagged'    => 0,
			'skipped'    => 0,
			'dirs_done'  => 0,
			'started'    => 0,
			'finished'   => 0,
			'core_stats' => array(),
			'message'    => '',
			'fim_new'    => 0,
			'fim_changed'=> 0,
			'fim_gone'   => 0,
			'fim_first'  => 0,
			'authentic'  => 0,
		);
	}

	/**
	 * Authenticity oracle, shared across the files in one batch.
	 *
	 * @var Ejabh_Verifier|null
	 */
	private static $verifier = null;

	/**
	 * Get (and lazily prepare) the verifier.
	 *
	 * @return Ejabh_Verifier
	 */
	private static function verifier() {
		if ( null === self::$verifier ) {
			// Defensive: a partial upload that lost this file must degrade to
			// "verify nothing, scan everything" rather than fataling mid-scan.
			if ( ! class_exists( 'Ejabh_Verifier' ) ) {
				self::$verifier = false;
				return false;
			}
			self::$verifier = new Ejabh_Verifier();
			self::$verifier->prepare();
		}
		return self::$verifier;
	}

	/**
	 * Read scan state.
	 *
	 * @return array
	 */
	public static function state() {
		$state = get_option( self::STATE_OPTION, array() );
		return is_array( $state ) && $state ? array_merge( self::blank_state(), $state ) : self::blank_state();
	}

	/**
	 * Persist scan state.
	 *
	 * @param array $state State array.
	 * @return void
	 */
	private static function save_state( array $state ) {
		update_option( self::STATE_OPTION, $state, false );
	}

	/**
	 * Begin a new scan: clear old findings and verify core checksums.
	 *
	 * @return array The new state.
	 */
	public static function start() {
		Ejabh_Findings::clear_type( 'file' );

		$scan_id = substr( md5( uniqid( 'dys', true ) ), 0, 16 );
		$state   = self::blank_state();

		$state['scan_id'] = $scan_id;
		$state['status']  = 'scanning';
		$state['started'] = time();
		$state['stack']   = array( untrailingslashit( Ejabh_Core_Integrity::root() ) );

		// On the very first run everything looks "new", so record the baseline
		// silently instead of reporting thousands of meaningless changes.
		$state['fim_first'] = ( Ejabh_Settings::get( 'fim_enabled' ) && ! Ejabh_FIM::has_baseline() ) ? 1 : 0;

		// Core verification is a single bounded step, so do it up front.
		$state['core_stats'] = Ejabh_Core_Integrity::run( $scan_id );

		self::save_state( $state );

		Ejabh_Logger::log( 'file_scan_started', 'بدأ فحص ملفات الاستضافة.', 'info' );

		return $state;
	}

	/**
	 * Process one batch of the queue.
	 *
	 * @return array Updated state.
	 */
	public static function step() {
		$state = self::state();

		if ( 'scanning' !== $state['status'] ) {
			return $state;
		}

		$budget   = max( 3, (int) Ejabh_Settings::get( 'scan_time_budget' ) );
		$deadline = microtime( true ) + $budget;
		$root     = Ejabh_Core_Integrity::root();
		$skip     = self::skip_list();
		$max_size = (int) Ejabh_Settings::get( 'scan_max_file_size' );

		while ( $state['stack'] && microtime( true ) < $deadline ) {
			$dir = array_pop( $state['stack'] );

			$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $entries ) {
				continue;
			}
			++$state['dirs_done'];

			foreach ( $entries as $entry ) {
				if ( '.' === $entry || '..' === $entry ) {
					continue;
				}

				$path = $dir . '/' . $entry;
				$rel  = Ejabh_Core_Integrity::relative( $path );

				if ( '' === $rel ) {
					continue;
				}

				// Never follow symlinks: they can leave the site root or loop.
				if ( is_link( $path ) ) {
					++$state['skipped'];
					continue;
				}

				if ( is_dir( $path ) ) {
					if ( self::is_skipped( $rel, $skip ) ) {
						++$state['skipped'];
						continue;
					}
					$state['stack'][] = $path;
					continue;
				}

				if ( ! is_file( $path ) ) {
					continue;
				}

				if ( self::is_skipped( $rel, $skip ) ) {
					++$state['skipped'];
					continue;
				}

				++$state['scanned'];
				$state['flagged'] += self::scan_file( $path, $rel, $state['scan_id'], $max_size, $state );
				self::track_changes( $path, $rel, $state );
			}
		}

		if ( ! $state['stack'] ) {
			$state['status']   = 'done';
			$state['finished'] = time();

			// Anything still carrying an older scan id has disappeared.
			if ( Ejabh_Settings::get( 'fim_enabled' ) ) {
				if ( ! $state['fim_first'] ) {
					$state['fim_gone'] = Ejabh_FIM::report_deletions( $state['scan_id'] );
				}
				Ejabh_FIM::prune_missing( $state['scan_id'] );
			}

			$counts = Ejabh_Findings::counts( 'file' );
			Ejabh_Logger::log(
				'file_scan_finished',
				sprintf(
					'انتهى فحص الملفات: %d ملف، %d نتيجة (حرج: %d، عالي: %d).',
					$state['scanned'],
					array_sum( $counts ),
					$counts['critical'],
					$counts['high']
				),
				$counts['critical'] > 0 ? 'critical' : 'info'
			);
		}

		self::save_state( $state );
		return $state;
	}

	/**
	 * Abort a running scan.
	 *
	 * @return void
	 */
	public static function cancel() {
		$state           = self::state();
		$state['status'] = 'idle';
		$state['stack']  = array();
		$state['message'] = __( 'أُلغي الفحص يدوياً.', 'ejabh-security' );
		self::save_state( $state );
	}

	/**
	 * Hash a file into the integrity baseline and report any change.
	 *
	 * @param string $path  Absolute path.
	 * @param string $rel   Site-relative path.
	 * @param array  $state Scan state, updated by reference.
	 * @return void
	 */
	private static function track_changes( $path, $rel, array &$state ) {
		if ( ! Ejabh_Settings::get( 'fim_enabled' ) ) {
			return;
		}

		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		// Hashing multi-hundred-megabyte files every scan is not worth the IO;
		// size and mtime still change-detect them adequately.
		if ( $size > 33554432 ) {
			$hash = md5( $rel . '|' . $size . '|' . (int) @filemtime( $path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		} else {
			$hash = @md5_file( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $hash ) {
				return;
			}
		}

		$mtime  = (int) @filemtime( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$status = Ejabh_FIM::record( $rel, $hash, $size, $mtime, $state['scan_id'] );

		if ( 'unchanged' === $status || $state['fim_first'] ) {
			return;
		}

		if ( 'new' === $status ) {
			++$state['fim_new'];
		} else {
			++$state['fim_changed'];
		}

		if ( Ejabh_FIM::report_change( $status, $rel, $state['scan_id'], $mtime ) ) {
			++$state['flagged'];
		}
	}

	/* ---------------------------------------------------------------------
	 * Single file analysis
	 * ------------------------------------------------------------------ */

	/**
	 * Apply every rule to one file.
	 *
	 * @param string $path     Absolute path.
	 * @param string $rel      Site-relative path.
	 * @param string $scan_id  Scan identifier.
	 * @param int    $max_size Largest file we will fully read.
	 * @param array  $state    Scan state, updated by reference.
	 * @return int Number of findings recorded.
	 */
	private static function scan_file( $path, $rel, $scan_id, $max_size, array &$state ) {
		$hits = 0;

		// 1. Path-based rules are free, so always run them.
		foreach ( Ejabh_Signatures::filenames() as $rule ) {
			if ( self::path_rule_exempt( $rule['id'], $path, $rel ) ) {
				continue;
			}
			if ( preg_match( $rule['regex'], $rel ) ) {
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'file',
						'severity'  => $rule['severity'],
						'rule'      => $rule['id'],
						'title'     => $rule['title'],
						'target'    => $rel,
						'snippet'   => sprintf(
							/* translators: 1: file size, 2: modified date. */
							__( 'الحجم: %1$s بايت — آخر تعديل: %2$s', 'ejabh-security' ),
							number_format_i18n( (int) @filesize( $path ) ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
							gmdate( 'Y-m-d H:i', (int) @filemtime( $path ) ) // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
						),
					)
				);
				++$hits;
			}
		}

		// The signature definitions themselves contain attack patterns as data.
		if ( false !== strpos( $rel, 'ejabh-security/includes/class-ejabh-signatures.php' ) ) {
			return $hits;
		}

		$ext  = strtolower( pathinfo( $rel, PATHINFO_EXTENSION ) );
		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$is_php  = in_array( $ext, self::PHP_EXT, true );
		$is_text = in_array( $ext, self::TEXT_EXT, true );

		if ( $is_php ) {
			if ( $size > $max_size ) {
				Ejabh_Findings::add(
					array(
						'scan_id'   => $scan_id,
						'scan_type' => 'file',
						'severity'  => 'medium',
						'rule'      => 'php_file_too_large',
						'title'     => __( 'ملف PHP أكبر من حد الفحص — يحتاج مراجعة يدوية', 'ejabh-security' ),
						'target'    => $rel,
						'snippet'   => sprintf(
							/* translators: %s: file size. */
							__( 'الحجم %s بايت يتجاوز حد الفحص المضبوط في الإعدادات.', 'ejabh-security' ),
							number_format_i18n( $size )
						),
					)
				);
				return $hits + 1;
			}
			$contents = self::read( $path, $max_size );
			if ( null === $contents ) {
				return $hits;
			}

			// A file that is byte-identical to an official release is authentic.
			// Pattern-matching it can only produce false positives: core really
			// does contain eval(), base64_decode() and wp_create_user().
			$verifier = self::verifier();
			if ( $verifier && $verifier->has_reference() && $verifier->is_authentic( $rel, $contents ) ) {
				++$state['authentic'];
				return $hits;
			}

			return $hits + self::apply_content_rules( $contents, $rel, $scan_id );
		}

		// Non-PHP file: look for smuggled PHP before doing any expensive work.
		if ( $size <= 0 ) {
			return $hits;
		}

		if ( $is_text ) {
			// Text formats are worth reading up to the configured limit; a huge
			// one is read partially rather than skipped.
			$limit = min( $size, $max_size );
		} else {
			// Binary/media: only worth opening if it is small enough that a
			// full read is cheap. Anything larger is left alone.
			if ( $size > self::MARKER_MAX_BYTES ) {
				return $hits;
			}
			$limit = $size;
		}

		$contents = self::read( $path, $limit );
		if ( null === $contents ) {
			return $hits;
		}

		if ( false === strpos( $contents, '<?php' ) && false === strpos( $contents, '<?=' ) ) {
			// No PHP — but a page can still be a phishing kit or leak
			// credentials to a Telegram bot.
			return $hits + self::apply_markup_rules( $contents, $rel, $scan_id );
		}

		Ejabh_Findings::add(
			array(
				'scan_id'   => $scan_id,
				'scan_type' => 'file',
				'severity'  => $is_text ? 'critical' : 'high',
				'rule'      => 'php_in_non_php_file',
				'title'     => __( 'كود PHP داخل ملف ليس امتداده PHP — تهريب باب خلفي', 'ejabh-security' ),
				'target'    => $rel,
				'snippet'   => self::excerpt_around( $contents, '<?php' ),
			)
		);
		++$hits;

		return $hits + self::apply_content_rules( $contents, $rel, $scan_id );
	}

	/**
	 * Suppress path rules in the cases that are always legitimate.
	 *
	 * @param string $rule_id Rule identifier.
	 * @param string $path    Absolute path.
	 * @param string $rel     Site-relative path.
	 * @return bool True to skip the rule.
	 */
	private static function path_rule_exempt( $rule_id, $path, $rel ) {
		// Our own protected directories legitimately hold blocked content.
		if ( 0 === strpos( $rel, 'wp-content/dys-quarantine/' ) || 0 === strpos( $rel, 'wp-content/dys-security-backups/' ) ) {
			return true;
		}

		if ( 'php_in_uploads' !== $rule_id ) {
			return false;
		}

		// WordPress and most plugins drop a stub index.php into every upload
		// subfolder to prevent directory listing. Flagging those as critical
		// buries the one file that actually matters.
		if ( 'index.php' !== strtolower( basename( $rel ) ) ) {
			return false;
		}

		$size = (int) @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( $size > 512 ) {
			return false;
		}

		$contents = self::read( $path, 512 );
		if ( null === $contents ) {
			return false;
		}

		// Strip the opening tag and comments; a genuine guard file has nothing left.
		$stripped = preg_replace( array( '/<\?php/i', '/\/\*.*?\*\//s', '/\/\/[^\n]*/', '/#[^\n]*/' ), '', $contents );

		return '' === trim( (string) $stripped );
	}

	/**
	 * Run the pattern and combo rules over file contents.
	 *
	 * @param string $contents File contents.
	 * @param string $rel      Site-relative path.
	 * @param string $scan_id  Scan identifier.
	 * @return int Findings recorded.
	 */
	private static function apply_content_rules( $contents, $rel, $scan_id ) {
		$hits     = 0;
		$vendored = self::is_vendored( $rel );

		foreach ( Ejabh_Signatures::patterns() as $rule ) {
			if ( ! preg_match( $rule['regex'], $contents, $m, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}

			$severity = $rule['severity'];

			// Third-party libraries legitimately use several of the noisier
			// functions. Keep the finding but stop it dominating the report.
			if ( $vendored && in_array( $severity, array( 'medium', 'high' ), true ) ) {
				$severity = 'low';
			}

			$offset = isset( $m[0][1] ) ? (int) $m[0][1] : 0;

			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => $severity,
					'rule'      => $rule['id'],
					'title'     => $rule['title'],
					'target'    => $rel,
					'line_no'   => self::line_at( $contents, $offset ),
					'snippet'   => self::excerpt_at( $contents, $offset ),
				)
			);
			++$hits;
		}

		foreach ( Ejabh_Signatures::combos() as $rule ) {
			$matched = true;
			$first   = 0;

			foreach ( $rule['all'] as $i => $regex ) {
				if ( ! preg_match( $regex, $contents, $m, PREG_OFFSET_CAPTURE ) ) {
					$matched = false;
					break;
				}
				if ( 0 === $i && isset( $m[0][1] ) ) {
					$first = (int) $m[0][1];
				}
			}

			if ( $matched && ! empty( $rule['none'] ) ) {
				foreach ( $rule['none'] as $regex ) {
					if ( preg_match( $regex, $contents ) ) {
						$matched = false;
						break;
					}
				}
			}

			if ( ! $matched ) {
				continue;
			}

			$severity = $rule['severity'];
			if ( $vendored && 'critical' !== $severity ) {
				$severity = 'medium';
			}

			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => $severity,
					'rule'      => $rule['id'],
					'title'     => $rule['title'],
					'target'    => $rel,
					'line_no'   => self::line_at( $contents, $first ),
					'snippet'   => self::excerpt_at( $contents, $first ),
				)
			);
			++$hits;
		}

		if ( Ejabh_Threat_Detector::phishing_applies( $rel ) ) {
			$hits += self::apply_phishing_rules( $contents, $rel, $scan_id );
		}

		return $hits;
	}

	/**
	 * Rules for files with no PHP in them: phishing pages and exfiltration.
	 *
	 * @param string $contents File contents.
	 * @param string $rel      Site-relative path.
	 * @param string $scan_id  Scan identifier.
	 * @return int Findings recorded.
	 */
	private static function apply_markup_rules( $contents, $rel, $scan_id ) {
		$hits = 0;

		foreach ( Ejabh_Threat_Detector::examine( $contents, $rel ) as $hit ) {
			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => $hit['severity'],
					'rule'      => $hit['id'],
					'title'     => $hit['title'],
					'target'    => $rel,
					'line_no'   => self::line_at( $contents, $hit['offset'] ),
					'snippet'   => self::excerpt_at( $contents, $hit['offset'] ),
				)
			);
			++$hits;
		}

		return $hits;
	}

	/**
	 * Phishing rules over a file that also contains PHP.
	 *
	 * @param string $contents File contents.
	 * @param string $rel      Site-relative path.
	 * @param string $scan_id  Scan identifier.
	 * @return int Findings recorded.
	 */
	private static function apply_phishing_rules( $contents, $rel, $scan_id ) {
		$hits = 0;

		foreach ( Ejabh_Signatures::phishing() as $rule ) {
			$offset = Ejabh_Threat_Detector::combo_offset( $rule, $contents );
			if ( null === $offset ) {
				continue;
			}
			Ejabh_Findings::add(
				array(
					'scan_id'   => $scan_id,
					'scan_type' => 'file',
					'severity'  => $rule['severity'],
					'rule'      => $rule['id'],
					'title'     => $rule['title'],
					'target'    => $rel,
					'line_no'   => self::line_at( $contents, $offset ),
					'snippet'   => self::excerpt_at( $contents, $offset ),
				)
			);
			++$hits;
		}

		return $hits;
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------ */

	/**
	 * Read up to N bytes of a file.
	 *
	 * @param string $path  Absolute path.
	 * @param int    $bytes Maximum bytes.
	 * @return string|null Null when unreadable.
	 */
	private static function read( $path, $bytes ) {
		if ( $bytes <= 0 || ! is_readable( $path ) ) {
			return null;
		}
		$data = @file_get_contents( $path, false, null, 0, $bytes ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		return false === $data ? null : $data;
	}

	/**
	 * Directory fragments to skip.
	 *
	 * @return array
	 */
	private static function skip_list() {
		$skip = (array) Ejabh_Settings::get( 'scan_skip_dirs' );
		return array_values( array_filter( array_map( 'trim', $skip ) ) );
	}

	/**
	 * Should this relative path be skipped?
	 *
	 * @param string $rel  Site-relative path.
	 * @param array  $skip Skip fragments.
	 * @return bool
	 */
	private static function is_skipped( $rel, array $skip ) {
		foreach ( $skip as $fragment ) {
			if ( '' === $fragment ) {
				continue;
			}
			if ( $rel === $fragment || 0 === strpos( $rel, $fragment . '/' ) || false !== strpos( $rel, '/' . $fragment . '/' ) || preg_match( '#(?:^|/)' . preg_quote( $fragment, '#' ) . '$#', $rel ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Is this path inside a third-party dependency tree?
	 *
	 * @param string $rel Site-relative path.
	 * @return bool
	 */
	private static function is_vendored( $rel ) {
		return (bool) preg_match( '#(?:^|/)(?:vendor|vendor_prefixed|vendor-patched|node_modules|lib/packages|dist|build|third-?party|packages)/#i', $rel )
			|| (bool) preg_match( '#(?:^|/)tests?/#i', $rel );
	}

	/**
	 * 1-indexed line number for a byte offset.
	 *
	 * @param string $contents File contents.
	 * @param int    $offset   Byte offset.
	 * @return int
	 */
	private static function line_at( $contents, $offset ) {
		if ( $offset <= 0 ) {
			return 1;
		}
		return substr_count( $contents, "\n", 0, min( $offset, strlen( $contents ) ) ) + 1;
	}

	/**
	 * Context around a byte offset.
	 *
	 * @param string $contents File contents.
	 * @param int    $offset   Byte offset.
	 * @return string
	 */
	private static function excerpt_at( $contents, $offset ) {
		$start   = max( 0, $offset - 120 );
		$excerpt = substr( $contents, $start, 400 );
		return trim( preg_replace( '/\s+/', ' ', $excerpt ) );
	}

	/**
	 * Context around the first occurrence of a needle.
	 *
	 * @param string $contents File contents.
	 * @param string $needle   Search string.
	 * @return string
	 */
	private static function excerpt_around( $contents, $needle ) {
		$pos = strpos( $contents, $needle );
		return self::excerpt_at( $contents, false === $pos ? 0 : $pos );
	}
}
