<?php
/**
 * Hardening checks with one-click fixes.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin  $admin
 * @var array      $checks
 * @var array|null $result
 */

defined( 'ABSPATH' ) || exit;

$icons = array(
	'ok'   => '✔',
	'warn' => '!',
	'fail' => '✖',
);

$fail_count = count(
	array_filter(
		$checks,
		static function ( $c ) {
			return 'fail' === $c['status'];
		}
	)
);
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-lock"></span> <?php esc_html_e( 'التحصين', 'ejabh-security' ); ?></h1>

	<?php if ( $result ) : ?>
		<div class="notice notice-<?php echo $result['ok'] ? 'success' : 'error'; ?> is-dismissible">
			<p><?php echo esc_html( $result['msg'] ); ?></p>
			<?php if ( ! empty( $result['backup'] ) ) : ?>
				<p class="description">
					<?php
					printf(
						/* translators: %s: backup file name. */
						esc_html__( 'نسخة احتياطية من wp-config.php محفوظة باسم %s داخل wp-content/dys-security-backups (محمي من الوصول عبر الويب).', 'ejabh-security' ),
						'<code>' . esc_html( $result['backup'] ) . '</code>'
					);
					?>
				</p>
			<?php endif; ?>
		</div>
	<?php endif; ?>

	<p class="description">
		<?php esc_html_e( 'كل بند هنا فُحص على السيرفر فعلياً. البنود التي يمكن إصلاحها آلياً لها زر إصلاح — والتعديلات على wp-config.php تُنشئ نسخة احتياطية وتتحقق من صياغة الملف قبل الكتابة، وتتراجع تلقائياً عند أي خطأ.', 'ejabh-security' ); ?>
	</p>

	<?php if ( $fail_count ) : ?>
		<div class="notice notice-error inline">
			<p><strong>
			<?php
			printf(
				/* translators: %d: number of failed checks. */
				esc_html__( '%d بند يحتاج إصلاحاً.', 'ejabh-security' ),
				(int) $fail_count
			);
			?>
			</strong></p>
		</div>
	<?php endif; ?>

	<table class="widefat striped ejabh-table">
		<thead>
			<tr>
				<th style="width:44px;"><?php esc_html_e( 'الحالة', 'ejabh-security' ); ?></th>
				<th style="width:26%;"><?php esc_html_e( 'البند', 'ejabh-security' ); ?></th>
				<th><?php esc_html_e( 'التفاصيل', 'ejabh-security' ); ?></th>
				<th style="width:190px;"><?php esc_html_e( 'الإصلاح', 'ejabh-security' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $checks as $check ) : ?>
			<tr>
				<td class="ejabh-status">
					<span class="ejabh-hs ejabh-hs--<?php echo esc_attr( $check['status'] ); ?>"><?php echo esc_html( $icons[ $check['status'] ] ); ?></span>
				</td>
				<td><strong><?php echo esc_html( $check['label'] ); ?></strong></td>
				<td>
					<?php echo esc_html( $check['detail'] ); ?>

					<?php if ( 'exposed' === $check['id'] && ! empty( $check['extra'] ) ) : ?>
						<table class="ejabh-subtable">
							<?php foreach ( $check['extra'] as $file ) : ?>
								<tr>
									<td><code><?php echo esc_html( $file['name'] ); ?></code></td>
									<td><?php echo esc_html( size_format( $file['size'] ) ); ?></td>
									<td>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
											onsubmit="return confirm('<?php echo esc_js( __( 'سيُحذف هذا الملف نهائياً من السيرفر. متابعة؟', 'ejabh-security' ) ); ?>');">
											<?php wp_nonce_field( 'dys_sec_harden' ); ?>
											<input type="hidden" name="action" value="dys_sec_harden" />
											<input type="hidden" name="fix" value="delete_exposed" />
											<input type="hidden" name="target" value="<?php echo esc_attr( $file['name'] ); ?>" />
											<button type="submit" class="button button-small"><?php esc_html_e( 'حذف الملف', 'ejabh-security' ); ?></button>
										</form>
									</td>
								</tr>
							<?php endforeach; ?>
						</table>
					<?php endif; ?>
				</td>
				<td>
					<?php if ( ! empty( $check['fix'] ) ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"
							<?php if ( ! empty( $check['warn'] ) ) : ?>
								onsubmit="return confirm('<?php echo esc_js( $check['warn'] ); ?>');"
							<?php endif; ?>>
							<?php wp_nonce_field( 'dys_sec_harden' ); ?>
							<input type="hidden" name="action" value="dys_sec_harden" />
							<input type="hidden" name="fix" value="<?php echo esc_attr( $check['fix'] ); ?>" />
							<button type="submit" class="button <?php echo 'fail' === $check['status'] ? 'button-primary' : ''; ?>">
								<?php echo esc_html( $check['button'] ); ?>
							</button>
						</form>
					<?php else : ?>
						<span class="ejabh-muted">—</span>
					<?php endif; ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'تصدير تقرير', 'ejabh-security' ); ?></h2>
	<p class="description"><?php esc_html_e( 'ملف HTML مستقل يجمع حالة التحصين ونتائج كل الفحوصات — يمكن فتحه في المتصفح وطباعته PDF وتسليمه للعميل.', 'ejabh-security' ); ?></p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'dys_sec_report' ); ?>
		<input type="hidden" name="action" value="dys_sec_report" />
		<button type="submit" class="button button-secondary">
			<span class="dashicons dashicons-download" style="vertical-align:text-bottom;"></span>
			<?php esc_html_e( 'تنزيل تقرير الحماية', 'ejabh-security' ); ?>
		</button>
	</form>
</div>
