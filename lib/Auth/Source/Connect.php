<?php

use InoOicClient\Oic\Authorization;
use Zend\Http\Request;
use InoOicClient\Oic\Token\Request as TokenRequest;
use InoOicClient\Client\ClientInfo;
use InoOicClient\Oic\Token\Dispatcher;
use InoOicClient\Oic\UserInfo\Dispatcher as InfoDispatcher;
use InoOicClient\Oic\UserInfo\Request as InfoRequest;

class sspmod_openidconnect_Auth_Source_Connect extends SimpleSAML_Auth_Source {

    protected $clientId;
    protected $clientSecret;
    protected $tokenEndpoint;
    protected $userInfoEndpoint;
    protected $authEndpoint;
    protected $sslcapath;

    public function __construct($info, $config) {
        /* Call the parent constructor first, as required by the interface. */
        parent::__construct($info, $config);

        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->tokenEndpoint = $config['token_endpoint'];
        $this->userInfoEndpoint = $config['user_info_endpoint'];
        $this->authEndpoint = $config['auth_endpoint'];
    }

    protected function getConfig() {
        return array(
            'client_info' => array(
                'client_id' => $this->clientId,
                'redirect_uri' => SimpleSAML_Module::getModuleURL('openidconnect/resume.php'),
                'authorization_endpoint' => $this->authEndpoint,
                'token_endpoint' => $this->tokenEndpoint,
                'user_info_endpoint' => $this->userInfoEndpoint,
                'authentication_info' => array(
                    'method' => 'client_secret_post',
                    'params' => array(
                        'client_secret' => $this->clientSecret,
                    ),
                ),
            ),
        );
    }

    public function authenticate(&$state) {
        $state['openidconnect:AuthID'] = $this->authId;
        $stateId = SimpleSAML_Auth_State::saveState($state, 'openidconnect:Connect');
        $info = $this->getConfig($stateId);

        \SimpleSAML\Utils\HTTP::redirectTrustedURL($info["client_info"]["authorization_endpoint"], array(
            "client_id"     => $info["client_info"]["client_id"],
            "redirect_uri"  => $info["client_info"]["redirect_uri"],
            "response_type" => "code",
            "state"         => $stateId
        ));
    }

    public static function requesturi() {
        if (isset($_SERVER['REQUEST_URI'])) {
            $uri = $_SERVER['REQUEST_URI'];
        }
        else {
            if (isset($_SERVER['argv'])) {
                $uri = $_SERVER['SCRIPT_NAME'] . '?' . $_SERVER['argv'][0];
            }
            elseif (isset($_SERVER['QUERY_STRING'])) {
                $uri = $_SERVER['SCRIPT_NAME'] . '?' . $_SERVER['QUERY_STRING'];
            }
            else {
                $uri = $_SERVER['SCRIPT_NAME'];
            }
        }
        $uri = '/' . ltrim($uri, '/');

        return $uri;
    }

    protected static function getAttributes($user) {
        foreach ($user as &$u) {
            if (!is_array($u)) {
                $u = array($u);
            }
        }
   
        $name = $user['name'][0];

        $stopwords = array("황목","황보", "남궁", "제갈");
        if(strlen($name) != mb_strlen($name, 'utf-8')) { 
            $name_chars = strlen($name);
            if($name_chars == 6) {
                $surname = mb_strcut($name, 0, 3);
                if(in_array($surname, $stopwords)){
                    $sn='';
                    $gn='';
                }else{ // no stop word
                    $sn = $surname;
                    $gn = mb_strcut($name, 3, strlen($name) - 3);
                }
            }else{ // do not separate sn and givenName
                if($name_chars > 6) {
                    $snt = mb_strcut($name, 0, 6);
                    if(in_array($snt, $stopwords)){
                        $sn = mb_strcut($snt, 0, 6);
                        $gn = mb_strcut($name, 6, strlen($name) - 6);
                    }else{
                        $sn = mb_strcut($snt, 0, 3);
                        $gn = mb_strcut($name, 3, strlen($name) - 3);
                    }
                }
            }
        }else{ //1-byte char
            $enm = explode(" ", $name);
            if( count($enm) > 1) {
                $gn = $enm[0];
                $sn = $enm[count($enm) -1 ];
            }else{
                $sn = '';
                $gn = '';
            }
        }
        $name = array("sn" => $sn, "gn" => $gn);

        $mapped = array(
            'urn:oid:2.5.4.3'    => $user['name'], // commonName
            'urn:oid:2.16.840.1.113730.3.1.241' => $user['nickname'], // displayName
            'urn:oid:2.5.4.4' => array($name['sn']), // surname
            'urn:oid:2.5.4.42' => array($name['gn']), // givenName
            'urn:oid:1.3.6.1.4.1.5923.1.1.1.6' => array(base64_encode(sha1($user['id'][0].".naver.com")) . "@kreonet.net"),
            'urn:oid:0.9.2342.19200300.100.1.3' => $user['email'], // email
        );

        return $mapped;
    }

    public static function resume() {
        $request = Request::fromString($_SERVER['REQUEST_METHOD'] . ' ' . self::requesturi());
        if (!$stateId = $request->getQuery('state')) {
            throw new SimpleSAML_Error_BadRequest('Missing "state" parameter.');
        }
        $state = SimpleSAML_Auth_State::loadState($stateId, 'openidconnect:Connect');
        
        $source = SimpleSAML_Auth_Source::getById($state['openidconnect:AuthID']);
        if ($source === NULL) {
            throw new SimpleSAML_Error_Exception('Could not find authentication source.');
        }
        
        if (! ($source instanceof self)) {
            throw new SimpleSAML_Error_Exception('Authentication source type changed.');
        }

        $tokenDispatcher = new Dispatcher();
        $tokenRequest = new TokenRequest();
        $clientInfo = new ClientInfo();

        $inf = reset($source->getConfig());
        $clientInfo->fromArray($inf);
        $tokenRequest->setClientInfo($clientInfo);
        $tokenRequest->setCode($request->getQuery('code'));
        $tokenRequest->setGrantType('authorization_code');

        $tokenResponse = $tokenDispatcher->sendTokenRequest($tokenRequest);

        $userDispatcher = new InfoDispatcher();

        $infoRequest = new InfoRequest();
        $infoRequest->setClientInfo($clientInfo);
        $infoRequest->setAccessToken($tokenResponse->getAccessToken());

        try {
            $infoResponse = $userDispatcher->sendUserInfoRequest($infoRequest);
            $user = $infoResponse->getClaims();
            $user = $user['response'];
        } catch (Exception $e) {
            throw new SimpleSAML_Error_Exception('User not authenticated after login attempt.', $e->getCode(), $e);
        }
       
        $attrs = self::getAttributes($user);
 
        $state['Attributes'] = $attrs;

        SimpleSAML_Auth_Source::completeAuth($state);
        assert('FALSE');
    }

    public function logout(&$state) {
        assert('is_array($state)');
        SimpleSAML_Module::callHooks('openidconnect_logout', $state);
    }

}
