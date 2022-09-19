# simplesamlphp-module-campususerpass

**REPOSITORY HAS BEEN MOVED TO: https://gitlab.ics.muni.cz/perun-proxy-aai/simplesamlphp/simplesamlphp-module-campususerpass**

This module extends authsource`SimpleSAML\Module\core\Auth\UserPassBase`. Thanks to this module, you can use [ECP](http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html) to log in the user. To achieve this, you just need to configure the authsource.

## Authsources configuration

First, you need to define and configure the authsource in authsources.php file. An example configuration is shown below:

    'campus-userpass' => [
        'campusUserPass:ECPAuth',

        'sp' => 'default-sp',
        'ecpIdpUrl' => 'https://ucn.id.muni.cz/ms-ucnmuni/saml2/idp/SSOService.php',
        'expectedIssuer' => 'https://ics.id.muni.cz/ms-ucnmuni/idp'
    ],

Let's look at the configuration options:

`campusUserPass:ECPAuth` defines which module and authentication source to use.

`sp` is an authsource with defined SP. It's needed to do the ECP request.

`ecpIdpUrl` is an ECP endpoint we want to call.

`expectedIssuer` is an expected issuer in the ECP response.

Of course, you also need to define [sp authsource](https://simplesamlphp.org/docs/latest/saml/sp.html) (`default-sp` in our case). When the configuration is done, the next step is to open `saml20-idp-hosted.php` file and set your authsource (`campus-userpass` in this example) as an authentication source (`auth` option).
