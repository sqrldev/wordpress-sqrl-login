<?php
include '../../../wp-load.php';

$wp_users = get_users(array(
	'meta_key'     => 'sqrl_session',
	'meta_value'   => $_GET['session'],
	'number'       => 1,
	'count_total'  => false,
	'fields'       => 'id',
));

if($wp_users[0]) {
	wp_set_auth_cookie( $wp_users[0] );

	delete_user_meta( $wp_users[0], 'sqrl_session');	
	
	header("Location: https://uhash.com", true);
}