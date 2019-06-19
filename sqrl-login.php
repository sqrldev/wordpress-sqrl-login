<?php
/**
 * Plugin Name:       SQRL Login
 * Description:       Login and Register your users using SQRL
 * Version:           0.0.1
 * Author:            Daniel Persson
 * Author URI:        http://danielpersson.dev
 * Text Domain:       sqrl
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * GitHub Plugin URI: http://github.com/kalaspuffar/wordpress-sqrl
 */

include "phpqrcode/qrlib.php";

class SQRLLogin{
	
    /**
     * SQRLLogin constructor.
     */
    public function __construct()
    {
		add_action('login_form', array($this, 'addToLoginForm'));
		
		add_action( 'admin_post_sqrl_login', array($this, 'loginCallback'));
        add_action( 'admin_post_nopriv_sqrl_login', array($this, 'loginCallback'));    
        add_action( 'admin_post_sqrl_auth', array($this, 'apiCallback'));
        add_action( 'admin_post_nopriv_sqrl_auth', array($this, 'apiCallback'));    				
	}
	
	function generateRandomString($length = 16) {
		return substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
	}	
	
    public function addToLoginForm() {
        if (get_option( 'users_can_register' )) {
            $button_label = __('Login or Register with SQRL', 'sqrl');
        } else {
            $button_label = __('Login with SQRL', 'sqrl');
        }

		$siteUrl = explode("://", get_site_url());
		$domainName = $siteUrl[0];
		if(count($siteUrl) == 2) {
			$domainName = $siteUrl[1];
		}
		
		$session = $this->generateRandomString();
		$nut = $this->generateRandomString();
		$sqrlURL = 'sqrl://' . $domainName . '/wp-admin/admin-post.php?action=sqrl_auth&nut=' . $nut . '-' . $session;
		
		ob_start();
		QRCode::png($sqrlURL, null);
		$imageString = base64_encode( ob_get_contents() );
		ob_end_clean();		
		
        $html = '<div id="sqrl-login-wrapper">';
        $html .= '<img src="data:image/png;base64,' . $imageString . '"/>';
		$html .= '<a id="sqrl" href="' . $sqrlURL . '" onclick="sqrlLinkClick(this);return true;" encoded-sqrl-url="' . $this->base64url_encode($sqrlURL) . '" tabindex="-1">'.$button_label.'</a>';
        $html .= '</div>';
		$html .= '<script type="text/javascript" src="' . plugins_url( 'pagesync.js', __FILE__ ) . '"></script>';
		$html .= '<script type="text/javascript" src="' . plugins_url( 'reload.js', __FILE__ ) . '"></script>';
		$html .= '<script type="text/javascript">window.sqrlSession = "' . $session . '"</script>';
				
        echo $html;
    }

	public function loginCallback() {
		$nutSession = explode('-', $_GET["nut"]);

		$wp_users = get_users(array(
			'meta_key'     => 'sqrl_session',
			'meta_value'   => $nutSession[1],
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));

		delete_user_meta( $wp_users[0], 'sqrl_session');
		wp_set_auth_cookie( $wp_users[0] );
		
        header("Location: " . get_site_url(), true);
        die();
	}
	
    public function apiCallback() {
		$clientStr = explode("\r\n", $this->base64url_decode($_POST["client"]));

		$client = array();
		foreach ($clientStr as $k => $v) {
			$p = explode("=", $v);
			$client[$p[0]] = $p[1];
		}
		
		$result = sodium_crypto_sign_verify_detached ($this->base64url_decode($_POST["ids"]), $_POST["client"] . $_POST["server"] , $this->base64url_decode($client["idk"]) );
			
		$serverStr = explode("\r\n", $this->base64url_decode($_POST["server"]));
		if(count($serverStr) == 1) {
			foreach (explode("&", $serverStr[0]) as $k => $v) {
				$p = explode("=", $v);
				$server[$p[0]] = $p[1];
			}
		} else {
			$server = array();
			foreach ($serverStr as $k => $v) {
				$p = explode("=", $v);
				$server[$p[0]] = $p[1];
			}			
		}
					
		$nutSession = explode('-', $server["nut"]);
		$nutSession[0] = $this->generateRandomString();
		
		$response = array();
		
		$response[] = "ver=1";
		$response[] = "nut=" . $nutSession[0] . '-' . $nutSession[1];
		$response[] = "qry=/wp-admin/admin-post.php?action=sqrl_auth&nut=" . $nutSession[0] . '-' . $nutSession[1];
		if($client['cmd'] == 'query') {
			if($this->accountPresent($client)) {
				$response[] = "tif=5";
			} else {
				$response[] = "tif=4";				
			}
		} else {
			$response[] = "tif=5";

			if(!$this->accountPresent($client)) {
				$this->createUser($client);
			}

			$this->addUserSession($client, $server);
			if(strpos($client['opt'], 'cps') !== false) {
				$response[] = "url=" . get_site_url() . "/wp-admin/admin-post.php?action=sqrl_login&nut=" . $nutSession[0] . '-' . $nutSession[1];
				$response[] = "can=" . get_site_url() . "?q=darn";
			}			
		}
		$response[] = "sin=0";
			
        echo $this->base64url_encode(implode("\r\n", $response));
    }

	private function createUser($client) {
		$new_user = wp_create_user($this->get_random_unique_username('user_'), wp_generate_password(), 'nobody@localhost');
		
		update_user_meta( $new_user, 'idk', $client['idk'] );
		update_user_meta( $new_user, 'suk', $client['suk'] );
		update_user_meta( $new_user, 'vuk', $client['vuk'] );
		
		$nutSession = explode('-', $server["nut"]);
		update_user_meta( $new_user, 'sqrl_session', $nutSession[1] );
	}

	private function addUserSession($client, $server) {
		$wp_users = get_users(array(
			'meta_key'     => 'idk',
			'meta_value'   => $client['idk'],
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));
		
		$nutSession = explode('-', $server["nut"]);

		update_user_meta( $wp_users[0], 'sqrl_session', $nutSession[1] );
	}	
	
	
	private function accountPresent($client) {
		$wp_users = get_users(array(
			'meta_key'     => 'idk',
			'meta_value'   => $client['idk'],
			'number'       => 1,
			'count_total'  => false,
			'fields'       => 'id',
		));
		
		if(empty($wp_users[0])) {
			return false;
		}
		return true;
	}	
	
	function get_random_unique_username( $prefix = '' ){
		$user_exists = 1;
		do {
		   $rnd_str = sprintf("%0d", mt_rand(1, 99999999999999));
		   $user_exists = username_exists( $prefix . $rnd_str );
	   } while( $user_exists > 0 );
	   return $prefix . $rnd_str;
	}
	
	function base64url_encode($data, $pad = null) {
		$data = str_replace(array('+', '/'), array('-', '_'), base64_encode($data));
		if (!$pad) {
			$data = rtrim($data, '=');
		}
		return $data;
	}
	function base64url_decode($data) {
		return base64_decode(str_replace(array('-', '_'), array('+', '/'), $data));
	}	
	
}

new SQRLLogin();