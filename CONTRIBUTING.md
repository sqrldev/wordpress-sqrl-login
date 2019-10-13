# Contributing to WordPress SQRL Login

First of thank you for considering helping out with this project. All contributions are welcome; we want this project to 
reach completion with a full implementation of the SQRL specification.

### I want to file a bug.

Then you open an issue under [issues](https://github.com/kalaspuffar/wordpress-sqrl-login/issues) and follow the guide there. Please search before you post, so we get a few duplicates as possible.

### I want to suggest a feature.

Then you open an issue under [issues](https://github.com/kalaspuffar/wordpress-sqrl-login/issues) and follow the guide there. Please search before you post, so we get a few duplicates as possible.

### I want to report a security vulnerability.

If the bug is none crucial and could be solved using the typical workflow, then report the issue in the same way as we usually file bugs. If the bug is sensitive, then email the project members, and we will address it as soon as possible.

### Testing

All new functions should include a valid unit test to ensure code quality going forward.

### Code style

We are trying to keep a consistent coding convention to help readability and make it easy to submit code.

The coding style is based on the standard WordPress ruleset with some exceptions that
made sense for this project.

* Class file name is inconsistent in the ruleset and not followed
* Nonce verification for forms can't be used as the client needs to follow the API
* Escaping the output is not required or valid because of API requests
* base64 encode and decode heavily used and accepted
* meta_key and meta_value is used for all SQRL values and warnings about performance is ignored
* Some print_r and error_log statements exist to ease error reporting.