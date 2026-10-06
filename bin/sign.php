<?php
/**
 * Sign or verify a release zip (Ed25519, detached, hex-encoded).
 *
 *   php bin/sign.php sign   <zip> <secret-key-file>   > <zip>.sig
 *   php bin/sign.php verify <zip> <sig-file>
 *
 * `verify` checks against the public key compiled into
 * includes/class-ejabh-updater.php — the same key every site will use — so a
 * release signed with the wrong key fails here, before it is published.
 */

if ( PHP_SAPI !== 'cli' ) {
	exit( 1 );
}

$mode = $argv[1] ?? '';
$zip  = $argv[2] ?? '';
$arg  = $argv[3] ?? '';

if ( ! is_file( $zip ) || ! is_file( $arg ) || ! in_array( $mode, array( 'sign', 'verify' ), true ) ) {
	fwrite( STDERR, "usage: php bin/sign.php sign|verify <zip> <key-or-sig-file>\n" );
	exit( 2 );
}

$data = file_get_contents( $zip );

if ( 'sign' === $mode ) {
	$secret = sodium_hex2bin( trim( file_get_contents( $arg ) ) );
	echo sodium_bin2hex( sodium_crypto_sign_detached( $data, $secret ) ), "\n";
	exit( 0 );
}

$source = file_get_contents( __DIR__ . '/../includes/class-ejabh-updater.php' );
if ( ! preg_match( "/const PUBLIC_KEY = '([0-9a-f]{64})'/", $source, $m ) ) {
	fwrite( STDERR, "public key not found in class-ejabh-updater.php\n" );
	exit( 3 );
}

$sig = sodium_hex2bin( trim( file_get_contents( $arg ) ) );
if ( sodium_crypto_sign_verify_detached( $sig, $data, sodium_hex2bin( $m[1] ) ) ) {
	echo "signature OK\n";
	exit( 0 );
}

fwrite( STDERR, "SIGNATURE DOES NOT MATCH the public key in the plugin\n" );
exit( 4 );
