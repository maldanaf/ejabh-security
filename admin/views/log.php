<?php
/**
 * Event log screen.
 *
 * @package Ejabh_Security
 *
 * @var Ejabh_Admin $admin
 * @var array     $rows
 * @var string    $severity
 */

defined( 'ABSPATH' ) || exit;

$base   = admin_url( 'admin.php?page=ejabh-security-log' );
$levels = array(
	''         => __( 'الكل', 'ejabh-security' ),
	'critical' => __( 'حرج', 'ejabh-security' ),
	'warning'  => __( 'تحذير', 'ejabh-security' ),
	'info'     => __( 'معلومة', 'ejabh-security' ),
);
?>
<div class="wrap ejabh-wrap">
	<h1><span class="dashicons dashicons-list-view"></span> <?php esc_html_e( 'سجل الأحداث الأمنية', 'ejabh-security' ); ?></h1>

	<p class="description">
		<?php esc_html_e( 'كل ما فعلته أو منعته الإضافة: محاولات الدخول، الرموز الخاطئة، الإضافات المحظورة، تغييرات الإعدادات، وإلغاء الجلسات. يُحتفظ بالسجل 90 يوماً.', 'ejabh-security' ); ?>
	</p>

	<ul class="subsubsub">
		<?php
		$parts = array();
		foreach ( $levels as $slug => $label ) {
			$url     = '' === $slug ? $base : add_query_arg( 'severity', $slug, $base );
			$parts[] = sprintf(
				'<li><a href="%s"%s>%s</a></li>',
				esc_url( $url ),
				$severity === $slug ? ' class="current"' : '',
				esc_html( $label )
			);
		}
		echo implode( ' | ', $parts ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		?>
	</ul>
	<div style="clear:both;"></div>

	<?php if ( ! $rows ) : ?>
		<p><?php esc_html_e( 'لا توجد أحداث مسجّلة.', 'ejabh-security' ); ?></p>
	<?php else : ?>
		<table class="widefat striped ejabh-table">
			<thead>
				<tr>
					<th style="width:80px;"><?php esc_html_e( 'الخطورة', 'ejabh-security' ); ?></th>
					<th style="width:160px;"><?php esc_html_e( 'الوقت (UTC)', 'ejabh-security' ); ?></th>
					<th style="width:170px;"><?php esc_html_e( 'الحدث', 'ejabh-security' ); ?></th>
					<th><?php esc_html_e( 'التفاصيل', 'ejabh-security' ); ?></th>
					<th style="width:130px;"><?php esc_html_e( 'IP', 'ejabh-security' ); ?></th>
					<th style="width:140px;"><?php esc_html_e( 'المستخدم', 'ejabh-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<?php $user = $row->user_id ? get_userdata( $row->user_id ) : null; ?>
					<tr>
						<td><?php echo wp_kses_post( $admin->severity_badge( $row->severity ) ); ?></td>
						<td>
							<?php echo esc_html( $row->created_at ); ?>
							<br /><span class="ejabh-muted"><?php echo esc_html( $admin->ago( $row->created_at ) ); ?></span>
						</td>
						<td><code><?php echo esc_html( $row->event ); ?></code></td>
						<td><?php echo esc_html( $row->message ); ?></td>
						<td><code><?php echo esc_html( $row->ip ? $row->ip : '—' ); ?></code></td>
						<td>
							<?php if ( $user ) : ?>
								<a href="<?php echo esc_url( get_edit_user_link( $user->ID ) ); ?>"><?php echo esc_html( $user->user_login ); ?></a>
							<?php else : ?>
								<span class="ejabh-muted">—</span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
