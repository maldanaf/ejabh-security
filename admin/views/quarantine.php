<?php
/**
 * Quarantined files and blocked IP addresses.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin  $admin
 * @var array      $rows
 * @var array      $blocks
 * @var array|null $result
 */

defined( 'ABSPATH' ) || exit;

$now = time();
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-shield"></span> <?php esc_html_e( 'الحجر الصحي والحظر', 'ejabh-security' ); ?></h1>

	<?php if ( $result ) : ?>
		<div class="notice notice-<?php echo $result['ok'] ? 'success' : 'error'; ?> is-dismissible">
			<p><?php echo esc_html( $result['msg'] ); ?></p>
		</div>
	<?php endif; ?>

	<h2><?php esc_html_e( 'الملفات المحجوزة', 'ejabh-security' ); ?></h2>
	<p class="description">
		<?php
		printf(
			/* translators: %s: quarantine directory path. */
			esc_html__( 'الملفات المشبوهة تُنقل إلى %s بدل حذفها. المجلد محمي بـ .htaccess ولا يمكن تنفيذ أي شيء بداخله ولا الوصول إليه عبر المتصفح — فإن تبيّن أن الملف سليم يمكن استعادته.', 'ejabh-security' ),
			'<code>wp-content/dys-quarantine</code>'
		);
		?>
	</p>

	<?php if ( ! $rows ) : ?>
		<p><?php esc_html_e( 'لا توجد ملفات محجوزة.', 'ejabh-security' ); ?></p>
	<?php else : ?>
		<table class="widefat striped ejabh-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'الملف الأصلي', 'ejabh-security' ); ?></th>
					<th style="width:90px;"><?php esc_html_e( 'الحجم', 'ejabh-security' ); ?></th>
					<th><?php esc_html_e( 'السبب', 'ejabh-security' ); ?></th>
					<th style="width:150px;"><?php esc_html_e( 'تاريخ الحجر', 'ejabh-security' ); ?></th>
					<th style="width:170px;"><?php esc_html_e( 'إجراء', 'ejabh-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $rows as $row ) : ?>
				<tr<?php echo $row->restored_at ? ' style="opacity:.55"' : ''; ?>>
					<td>
						<code class="ejabh-target"><?php echo esc_html( $row->original_path ); ?></code>
						<br /><span class="ejabh-muted" dir="ltr">md5: <?php echo esc_html( $row->hash ); ?></span>
					</td>
					<td><?php echo esc_html( size_format( (int) $row->size ) ); ?></td>
					<td><?php echo esc_html( $row->reason ); ?></td>
					<td>
						<?php echo esc_html( $row->quarantined_at ); ?>
						<br /><span class="ejabh-muted"><?php echo esc_html( $admin->ago( $row->quarantined_at ) ); ?></span>
					</td>
					<td>
						<?php if ( $row->restored_at ) : ?>
							<span class="ejabh-badge ejabh-badge--low"><?php esc_html_e( 'استُعيد', 'ejabh-security' ); ?></span>
						<?php else : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ejabh-inline-form"
								onsubmit="return confirm('<?php echo esc_js( __( 'إعادة الملف إلى مكانه الأصلي؟ إن كان مصاباً فستعيد الباب الخلفي.', 'ejabh-security' ) ); ?>');">
								<?php wp_nonce_field( 'dys_sec_quarantine' ); ?>
								<input type="hidden" name="action" value="dys_sec_quarantine" />
								<input type="hidden" name="what" value="restore" />
								<input type="hidden" name="id" value="<?php echo esc_attr( $row->id ); ?>" />
								<button type="submit" class="button button-small"><?php esc_html_e( 'استعادة', 'ejabh-security' ); ?></button>
							</form>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ejabh-inline-form"
								onsubmit="return confirm('<?php echo esc_js( __( 'حذف نهائي لا يمكن التراجع عنه. متابعة؟', 'ejabh-security' ) ); ?>');">
								<?php wp_nonce_field( 'dys_sec_quarantine' ); ?>
								<input type="hidden" name="action" value="dys_sec_quarantine" />
								<input type="hidden" name="what" value="purge" />
								<input type="hidden" name="id" value="<?php echo esc_attr( $row->id ); ?>" />
								<button type="submit" class="button button-small"><?php esc_html_e( 'حذف نهائي', 'ejabh-security' ); ?></button>
							</form>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>

	<h2><?php esc_html_e( 'محاولات الدخول والعناوين المحظورة', 'ejabh-security' ); ?></h2>
	<p class="description">
		<?php
		printf(
			/* translators: 1: max attempts, 2: window minutes, 3: lockout minutes. */
			esc_html__( 'الإعداد الحالي: %1$d محاولات فاشلة خلال %2$d دقيقة تؤدي إلى حظر العنوان %3$d دقيقة. الرمز الخاطئ في المصادقة الثنائية يُحتسب كمحاولة فاشلة أيضاً.', 'ejabh-security' ),
			(int) Ejabh_Settings::get( 'login_max_attempts' ),
			(int) Ejabh_Settings::get( 'login_window_mins' ),
			(int) Ejabh_Settings::get( 'login_lockout_mins' )
		);
		?>
	</p>

	<?php if ( ! $blocks ) : ?>
		<p><?php esc_html_e( 'لا توجد محاولات دخول فاشلة مسجّلة.', 'ejabh-security' ); ?></p>
	<?php else : ?>
		<table class="widefat striped ejabh-table">
			<thead>
				<tr>
					<th style="width:140px;"><?php esc_html_e( 'عنوان IP', 'ejabh-security' ); ?></th>
					<th style="width:80px;"><?php esc_html_e( 'محاولات', 'ejabh-security' ); ?></th>
					<th><?php esc_html_e( 'آخر اسم مستخدم مُجرَّب', 'ejabh-security' ); ?></th>
					<th style="width:160px;"><?php esc_html_e( 'آخر محاولة', 'ejabh-security' ); ?></th>
					<th style="width:170px;"><?php esc_html_e( 'الحالة', 'ejabh-security' ); ?></th>
					<th style="width:110px;"></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $blocks as $row ) : ?>
				<?php
				$until   = $row->blocked_until ? strtotime( $row->blocked_until . ' UTC' ) : 0;
				$active  = $until && $until > $now;
				?>
				<tr<?php echo $active ? ' class="ejabh-expired"' : ''; ?>>
					<td><code><?php echo esc_html( $row->ip ); ?></code></td>
					<td><?php echo esc_html( number_format_i18n( (int) $row->failures ) ); ?></td>
					<td><code><?php echo esc_html( $row->last_user ? $row->last_user : '—' ); ?></code></td>
					<td>
						<?php echo esc_html( $row->last_failure ); ?>
						<br /><span class="ejabh-muted"><?php echo esc_html( $admin->ago( $row->last_failure ) ); ?></span>
					</td>
					<td>
						<?php if ( $active ) : ?>
							<span class="ejabh-badge ejabh-badge--critical"><?php esc_html_e( 'محظور', 'ejabh-security' ); ?></span>
							<br /><span class="ejabh-muted">
								<?php
								printf(
									/* translators: %s: relative time. */
									esc_html__( 'ينتهي %s', 'ejabh-security' ),
									esc_html( $admin->ago( $until ) )
								);
								?>
							</span>
						<?php else : ?>
							<span class="ejabh-muted"><?php esc_html_e( 'يُراقَب فقط', 'ejabh-security' ); ?></span>
						<?php endif; ?>
					</td>
					<td>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
							<?php wp_nonce_field( 'dys_sec_quarantine' ); ?>
							<input type="hidden" name="action" value="dys_sec_unblock_ip" />
							<input type="hidden" name="ip" value="<?php echo esc_attr( $row->ip ); ?>" />
							<button type="submit" class="button button-small"><?php esc_html_e( 'رفع الحظر', 'ejabh-security' ); ?></button>
						</form>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
