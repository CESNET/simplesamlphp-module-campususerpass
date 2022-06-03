<?php

declare(strict_types=1);

namespace SimpleSAML\Module\campusUserPass\Auth\Source;

use SAML2\Assertion;
use SAML2\DOMDocumentFactory;
use SAML2\Message;
use SAML2\Utils;
use SAML2\XML\saml\Issuer;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Error\AuthSource;
use SimpleSAML\Error\Error;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\core\Auth\UserPassBase;
use SimpleSAML\Store;
use SimpleSAML\Utils\HTTP;
use SimpleXMLElement;

class ECPAuth extends UserPassBase
{
    private $sp;
    private $ecpIdpUrl;

    public function __construct($info, $config)
    {
        parent::__construct($info, $config);

        $this->sp = $config['sp'];
        if (empty($this->sp)) {
            throw new Exception('Missing mandatory configuration option \'sp\'.');
        }

        $this->ecpIdpUrl = $config['ecpIdpUrl'];
        if (empty($this->ecpIdpUrl)) {
            throw new Exception('Missing mandatory configuration option \'ecpIdpUrl\'.');
        }

        $this->expectedIssuer = $config['expectedIssuer'];
        if (empty($this->expectedIssuer)) {
            throw new Exception('Missing mandatory configuration option \'expectedIssuer\'.');
        }
    }

    public function authenticate(&$state)
    {
        $state[ECPAuth::AUTHID] = $this->getAuthId();
        $id = State::saveState($state, self::STAGEID);

        $source = Source::getById($state[ECPAuth::AUTHID]);
        if ($source === null) {
            throw new \Exception(
                'Could not find authentication source with id ' . $state[UserPassBase::AUTHID]
            );
        }

        if (array_key_exists('username', $_POST)) {
            $username = $_POST['username'];
        } elseif ($source->getRememberUsernameEnabled() && array_key_exists($source->getAuthId() . '-username', $_COOKIE)) {
            $username = $_COOKIE[$source->getAuthId() . '-username'];
        } elseif (isset($state['core:username'])) {
            $username = (string) $state['core:username'];
        } else {
            $username = '';
        }

        if (array_key_exists('password', $_POST)) {
            $password = $_POST['password'];
        } else {
            $password = '';
        }

        if (!empty($_POST['username']) || !empty($password)) {
            // Either username or password set - attempt to log in

            if (array_key_exists('forcedUsername', $state)) {
                $username = $state['forcedUsername'];
            }

            if ($source->getRememberUsernameEnabled()) {
                $sessionHandler = \SimpleSAML\SessionHandler::getSessionHandler();
                $params = $sessionHandler->getCookieParams();

                if (isset($_REQUEST['remember_username']) && $_REQUEST['remember_username'] == 'Yes') {
                    $params['expire'] = time() + 31536000;
                } else {
                    $params['expire'] = time() - 300;
                }
                HTTP::setCookie($source->getAuthId() . '-username', $username, $params, false);
            }

            try {
                UserPassBase::handleLogin($id, $username, $password);
            } catch (\SimpleSAML\Error\Error $e) {
                // Login failed. Extract error code and parameters, to display the error
                $errorCode = $e->getErrorCode();
                $errorParams = $e->getParameters();
                $state['error'] = [
                    'code' => $errorCode,
                    'params' => $errorParams
                ];
                $id = State::saveState($state, UserPassBase::STAGEID);
            }
            if (isset($state['error'])) {
                unset($state['error']);
            }
        }

        $url = Module::getModuleURL('campusMultiauth/selectsource.php');
        HTTP::redirectTrustedURL($url, ['AuthState' => $id, 'wrongUserPass' => true]);
    }

    protected function login($username, $password)
    {
        $source = Source::getById($this->sp);
        if ($source === null) {
            throw new AuthSource($this->sp, 'Could not find authentication source.');
        }

        $spMetadata = $source->getMetadata();

        $xml = new SimpleXMLElement(
            '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"></S:Envelope>'
        );

        $xmlBody = $xml->addChild('S:Body');
        $xmlRequest = $xmlBody->addChild(
            'samlp:AuthnRequest',
            null,
            'urn:oasis:names:tc:SAML:2.0:protocol'
        );
        $xmlRequest->addAttribute('ID', '' . rand() . '');
        $xmlRequest->addAttribute('IssueInstant', '' . gmdate('Y-m-d\TH:i:s\Z', time()) . '');
        $xmlRequest->addAttribute('Version', '2.0');
        $xmlRequest->addAttribute('AssertionConsumerServiceIndex', '2');

        $xmlRequest->addChild(
            'saml:Issuer',
            $spMetadata->getString('entityid'),
            'urn:oasis:names:tc:SAML:2.0:assertion'
        );

        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $this->ecpIdpUrl);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xml->asXML());
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: text/xml']);
        curl_setopt($ch, CURLOPT_USERPWD, $username . ':' . $password);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        $response = curl_exec($ch);
        curl_close($ch);

        $document = DOMDocumentFactory::fromString($response);
        $xml = $document->firstChild;
        $results = Utils::xpQuery($xml, '/soap-env:Envelope/soap-env:Body/*[1]');
        $response = Message::fromXML($results[0]);

        $issuer = $response->getIssuer();
        if ($issuer === null) {
            foreach ($response->getAssertions() as $a) {
                if ($a instanceof Assertion) {
                    $issuer = $a->getIssuer();
                    break;
                }
            }
            if ($issuer === null) {
                throw new Exception('Missing <saml:Issuer> in message delivered to AssertionConsumerService.');
            }
        }
        if ($issuer instanceof Issuer) {
            $issuer = $issuer->getValue();
            if ($issuer === null) {
                throw new Exception('Missing <saml:Issuer> in message delivered to AssertionConsumerService.');
            }
        }
        if ($this->expectedIssuer !== $issuer) {
            throw new Exception('Unexpected issuer in the ECP response');
        }

        $idpMetadata = $source->getIdPmetadata($issuer);
        Logger::debug('Received SAML2 Response from ' . var_export($issuer, true) . '.');

        try {
            $assertions = Module\saml\Message::processResponse($spMetadata, $idpMetadata, $response);
        } catch (Module\saml\Error $e) {
            if (str_contains($e->getMessage(), 'WRONGUSERPASS')) {
                throw new Error('WRONGUSERPASS');
            }

            throw new Exception('Error while processing the response: ' . $e);
        }

        $attributes = [];
        foreach ($assertions as $assertion) {
            // check for duplicate assertion (replay attack)
            $store = Store::getInstance();
            if ($store !== false) {
                $aID = $assertion->getId();
                if ($store->get('saml.AssertionReceived', $aID) !== null) {
                    throw new Exception('Received duplicate assertion.');
                }

                $notOnOrAfter = $assertion->getNotOnOrAfter();
                if ($notOnOrAfter === null) {
                    $notOnOrAfter = time() + 24 * 60 * 60;
                } else {
                    $notOnOrAfter += 60; // we allow 60 seconds clock skew, so add it here also
                }

                $store->set('saml.AssertionReceived', $aID, true, $notOnOrAfter);
            }

            $attributes = array_merge($attributes, $assertion->getAttributes());
        }

        return $attributes;
    }
}
