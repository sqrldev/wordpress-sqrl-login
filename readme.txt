=== SQRL Login ===
Contributors: kalaspuffar
Tags: sqrl, login
Donate link: http://ko-fi.com/danielpersson
Requires at least: 5.2.2
Tested up to: 5.9.1
Requires PHP: 7.2
Stable tag: trunk
License: MIT
License URI: https://raw.githubusercontent.com/kalaspuffar/wordpress-sqrl-login/master/LICENSE

Secure Quick Reliable Login, this plugin will enable logging in using SQRL clients.

== Description ==
SQRL can be used to log in to a site in a secure manner without giving away any personal information. This plugin enables that functionallity.

Instead of using a username, email and a password, SQRL uses an app to login to SQRL-aware websites.

When SQRL logs you into a website, your identity is a long code that looks like this: E6Qs2gX7W-Pwi9Y3KAmbkuYjLSWXCtKyBcymWloHAuo.

Your SQRL identity is a different long code for every website you login to, but it is always the same code when you return to a site you visited before. This means that websites never know who you are, but they do know when you return.

You may choose to remain anonymous to a website, such as when you post a response to someone's blog. SQRL never identifies you by anything other than that long code.

In other cases you will want to be known, like when you use SQRL to login as you at Amazon, Facebook, Netflix, or your bank. In those cases, you would inform Amazon that that particular code is actually you. SQRL lets you do that.

Special thanks to:

@davidshimjs (Sangmin, Shim) for writing a great javascript library for QRCode creation. (https://github.com/davidshimjs/qrcodejs)
@jaredatch (Jared Atchison) for writing a plugin for disabling users that I took inspiration from. (https://github.com/jaredatch/Disable-Users)

== Installation ==
1. Ensure that your site is using SSL. It's using a https connection.
2. Install the plugin.
3. Enable the plugin.
4. Verify that your login screen has a login screen similar to the screenshot on the details page.

== Screenshots ==
1. Login screen with enabled SQRL Login
2. Profile screen when no SQRL identity is associated
3. Profile screen with SQRL identity is associated

== Changelog ==

Version 2.1.0

* Changed login page design to make it clearer for new users.
* Fixing registration selection page style.

Version 2.0.0

* Multiple changes when introducing a test suite testing all vital paths.

Version 1.2.0

Features
* Added registration page.

Bugfixes
* Remove notice due to redirect_to (Thanks to @sanzeeb3)
* Handle issue "Google Crawl causes Exception" (Issue #36)

Version 1.1.2

Bugfixes
* White border around QRCode.

Version 1.1.1

Bugfixes
* Handle CANcel parameter correctly.
* Remove should disassociate identity from user
* Disable should only disable login with SQRL if not SQRLOnly is supplied.

Version 1.1.0

Improvements
* Use transient session for all login data.
* Handle case where user registration is not allowed

Bugfixes
* Javascript fixes to handle load issues.

Version 1.0.0

Improvements
* Update meta_key values to have prefix.
* Warn users who don't have SSL enabled.

Version 0.8.0

Features
* Redirect URL setting
* Handle options hardlock and sqrlonly.

Improvements
* Better session handling

Bugfixes
* Added line-break after the last line.

Version 0.7.0

Features
* Handle redirect urls.
* Fix content length.

Version 0.6.4

Improvements
* Added content length
* Added path length for all return qry

Version 0.6.3

Improvements
* Visualize enabling, disabling and removing better.

Version 0.6.2

Bugfixes
* User association fix.

Version 0.6.1

Bugfixes
* Fixing styling issues.

Version 0.6.0

Features
* Using a javascript library to create QRCode
* Correctly check ip address during log in.
* Added functionallity to disable, enable and remove users.

Improvements
* Improved profile design.

Version 0.5.1

Bugfixes
* Handle new strpos function requirements in PHP 7.3

Version 0.5.0

Features
* Handle sub path installations. Eg. https://domain.com/wordpress_path/
* Keep user on the profile page if associating an existing user.

Version 0.4.1

Bugfixes
* Didn't handle empty values correctly when looking for users.

Version 0.4.0

Features
* Handle previous keys

Bugfixes
* Reassociate correctly when registration is not allowed.

Version 0.3.0

Features
* Better error handling
* Disallow users to register if not allowed by server.

Version 0.2.3

Bugfixes
* Remove dependency to test site.

Version 0.2.2
* Added comments to increase readability.

Version 0.2.0
* Improvements to meet WordPress plugin guidelines.

Version 0.1.0
* Clean up and working towards a usable plugin to login

Version 0.0.1
* Proof of concept

== Upgrade Notice ==
== Frequently Asked Questions ==
