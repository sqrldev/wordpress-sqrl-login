<?php

class PluginTest extends WP_UnitTestCase {

  // Check that that activation doesn't break
  function test_plugin_activated() {
    $this->assertTrue( is_plugin_active( PLUGIN_PATH ) );
  }

  function test_user_login_message() {
    $_SERVER['HTTPS'] = 0;
    $message = SQRLLogin::user_login_message();
    $this->assertEqual( "SQRL Login is only available for sites utilizing SSL connections. Please activate SSL before using SQRL Login.", $message );

    $_SERVER['HTTPS'] = 1;
    $message = SQRLLogin::user_login_message();
    $this->assertEqual( "", $message );

    $message = SQRLLogin::user_login_message(SQRLLogin::MESSAGE_DISABLED);
    $this->assertEqual( "Account disabled", $message );

    $message = SQRLLogin::user_login_message(SQRLLogin::MESSAGE_REMOVED);
    $this->assertEqual( "Identity disassociated from account", $message );

    $message = SQRLLogin::user_login_message(SQRLLogin::MESSAGE_SQRLONLY);
    $this->assertEqual( "The only allowed login method is SQRL for this account", $message );

    $message = SQRLLogin::user_login_message(SQRLLogin::MESSAGE_ERROR);
    $this->assertEqual( "An error occured with the last SQRL command, please try again.", $message );

    $message = SQRLLogin::user_login_message(SQRLLogin::MESSAGE_REGISTRATION_NOT_ALLOWED);
    $this->assertEqual( "The site is not allowing new registrations and your SQRL identity is not associated with any account.", $message );
  }
}

