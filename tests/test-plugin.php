<?php

class PluginTest extends WP_UnitTestCase {

  // Check that that activation doesn't break
  function test_plugin_activated() {
    $this->assertTrue( is_plugin_active( PLUGIN_PATH ) );
  }

  function test_user_login_message() {
    $sqrlLogin = new SQRLLogin();

    $_SERVER['HTTPS'] = 0;
    $message = $sqrlLogin->user_login_message();
    $this->assertEqual( "SQRL Login is only available for sites utilizing SSL connections. Please activate SSL before using SQRL Login.", $message );

    $_SERVER['HTTPS'] = 1;
    $message = $sqrlLogin->user_login_message(); 
    $this->assertEqual( "", $message );

    $_GET['message'] = SQRLLogin::MESSAGE_DISABLED;
    $message = $sqrlLogin->user_login_message();
    $this->assertEqual( "Account disabled", $message );

    $_GET['message'] = SQRLLogin::MESSAGE_REMOVED;
    $message = $sqrlLogin->user_login_message();
    $this->assertEqual( "Identity disassociated from account", $message );

    $_GET['message'] = SQRLLogin::MESSAGE_SQRLONLY;
    $message = $sqrlLogin->user_login_message();
    $this->assertEqual( "The only allowed login method is SQRL for this account", $message );

    $_GET['message'] = SQRLLogin::MESSAGE_ERROR;
    $message = $sqrlLogin->user_login_message();
    $this->assertEqual( "An error occured with the last SQRL command, please try again.", $message );

    $_GET['message'] = SQRLLogin::MESSAGE_REGISTRATION_NOT_ALLOWED;
    $message = $sqrlLogin->user_login_message();
    $this->assertEqual( "The site is not allowing new registrations and your SQRL identity is not associated with any account.", $message );
  }
}

