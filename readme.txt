=== sqrl-login ===
Contributors: Daniel Persson
Tags: sqrl, login
Donate link: http://ko-fi.com/danielpersson
Requires at least: 5.2.2
Tested up to: 5.2.2
Requires PHP: 7.0
Stable tag: trunk
License: MIT
License URI: https://raw.githubusercontent.com/kalaspuffar/wordpress-sqrl-login/master/LICENSE

Secure Quick Reliable Login, this plugin will enable logging in using SQRL clients.

== Description ==
Before you begin using SQRL to log in to websites, your SQRL private identity must be created. You only need one, probably for life, because it reveals NOTHING about you, and it\'s highly secure. It\'s just a very long (77-digit) random number.

From then on, whenever you log in with SQRL to a website, your private identity is used to generate another 77-digit number for that one website. Every website you visit sees you as a different number, yet every time you return to the same site, that site\'s unique number is regenerated.

This allows you to be uniquely and permanently identified, yet completely anonymous.

Since you never need to use an email address or a password, you never give a website your actual identity to protect. If the website\'s SQRL identities are ever stolen, not only would the stolen identities only be valid for that one website, but SQRL\'s cryptography prevents impersonation by using stolen identities.

This is as good as it sounds. It\'s what we\'ve been waiting for.

== Installation ==
Add and enable

== Frequently Asked Questions ==

== Screenshots ==
1. Login screen with enabled SQRL Login

== Changelog ==
== Upgrade Notice ==
