# Contributing to WordPress SQRL Login

First of thank you for considering helping out with this project. All contributions are welcome, we want this project to 
reach completion with a full implementation of the SQRL specification.

### I want to file a bug.

Then you open an issue under [issues](https://github.com/kalaspuffar/wordpress-sqrl-login/issues) and follow the 
guide there. Please search before you post so we get as few duplicates as possible.

### I want to suggest a feature.

Then you open an issue under [issues](https://github.com/kalaspuffar/wordpress-sqrl-login/issues) and follow the 
guide there. Please search before you post so we get as few duplicates as possible.

### I want to report a security vulnerability.

If the bug is none crusial and could be solved using the normal workflow then report the issue in the same way as we usually file bugs. If the bug is of a sensitive nature then email the project members and we will address it as soon as possible.

### Code style

We are trying to keep an consistant coding convention in order to help readablility and make it easy to submit code.

The coding style is based on the standard WordPress ruleset with some exceptions that
made sense for this project.

* Class file name is inconsistant in the ruleset and not followed
* Nonce verification for forms can't be used as the client need to follow the API
* Escaping the output is not required or valid because of API requests
* base64 encode and decode is heavily used and accepted
* meta_key and meta_value is used for all SQRL values and warnings about performance is ignored
* Some print_r and error_log statements exists to ease error reporting.