# EmailAuth
A library to authenticate via an arbitrary email. Can be used in the projects where one doesn't need to keep a user entity in the database, but for which at the same time an authentication with service providers like Google is not enough.

# Installation
* Install Composer: https://getcomposer.org/download
* Add ```"punarinta/email-auth": "dev-master"``` line into the "require" section of your composer.json file
* Run ```php composer.phar install```
* Assure "autoload.php" file from vendor directory is included

# Sample usage
```
use \EmailAuth\Auth;

$auth = new Auth;
if ($auth->login('your@email', 'your-passwpord'))
{
  // You are authenticated.
}
elseif ($auth->status == Auth::STATUS_OAUTH_NEEDED)
{
  // Please authenticate via OAuth.
}
else
{
  // Thou shalt not pass!
}
```

# Troubleshooting
##### Fatal error: Call to undefined function imap_open()
No IMAP module is installed for PHP. Here's an example for PHP7 and Ubuntu how to fix it.
```
sudo apt-get install php7.0-imap
sudo phpenmod imap
```

# License
This project is licensed under the terms of [**MIT**](https://github.com/punarinta/email-auth/blob/master/LICENSE) license.