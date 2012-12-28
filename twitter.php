<?php

$consumer_key = /* YOUR CONSUMER KEY */;
$consumer_key_secret = /* YOUR CONSUMER KEY SECRET */;
$access_token = /* YOUR ACCESS TOKEN */;
$access_token_secret = /* YOUR ACCESS TOKEN SECRET */;

$function = /* THE FUNCTION YOU WISH TO CALL:  postTweet, getFollowers, getFollowing, follow, unfollow */;
$params = /* PARAMETERS FOR THE FUNCTION (ex: "kevinrose" for "follow") */;


$twitter = new Twitter();
$auth = $twitter->oauth($consumer_key, $consumer_key_secret, $access_token, $access_token_secret);
if ($auth) {
	switch($function) {
		case "postTweet": $result = $twitter->call('statuses/update', array('status' => $params)); if (!$result->error) $success = true; break;
		case "getFollowers":
			$statusfollows = $twitter->call('statuses/followers');
			foreach ($statusfollows as $n => $info) {
				foreach ((array)$info as $k => $v) $followers[$n][$k] = $v;
			}
			processFollowers($followers); break;
		case "getFollowing":
			$statusfollows = $twitter->call('statuses/friends');
			foreach ($statusfollows as $n => $info) {
				foreach ((array)$info as $k => $v) $followers[$n][$k] = $v;
			}
			processFollowers($followers); break;			
		case "follow": 
			$whoms = explode(",", $params);
			foreach ($whoms as $whom) {
				$test = $twitter->call('friendships/create', array('screen_name' => trim($whom)));
				$test = $twitter->call('notifications/follow', array('screen_name' => trim($whom)));
				if (!$test->error) $result = true;
			}
			if ($result) $success = true; 
			break;
		case "unfollow": 
			$whoms = explode(",", $params);
			foreach ($whoms as $whom) {			
				$test = $twitter->call('notifications/leave', array('screen_name' => trim($whom)));
				$test = $twitter->call('friendships/destroy', array('screen_name' => trim($whom)));
				if (!$test->error) $result = true;
			}
			if ($result) $success = true; 
			break;				

		default: break;
	}
}

if ($success) echo 'success'; else { echo 'failure'; }

class EpiOAuth {
	public $version = '1.0';

	protected $requestTokenUrl;
	protected $accessTokenUrl;
	protected $authorizeUrl;
	protected $consumerKey;
	protected $consumerSecret;
	protected $token;
	protected $tokenSecret;
	protected $signatureMethod;

	public function getAccessToken()
	{
		$resp = $this->httpRequest('GET', $this->accessTokenUrl);
		return new EpiOAuthResponse($resp);
	}

	public function getAuthorizationUrl()
	{
		$retval = "{$this->authorizeUrl}?";

		$token = $this->getRequestToken();
		return $this->authorizeUrl . '?oauth_token=' . $token->oauth_token;
	}

	public function getRequestToken()
	{
		$resp = $this->httpRequest('GET', $this->requestTokenUrl);
		return new EpiOAuthResponse($resp);
	}

	public function httpRequest($method = null, $url = null, $params = null)
	{
		if(empty($method) || empty($url))
			return false;

		if(empty($params['oauth_signature']))
			$params = $this->prepareParameters($method, $url, $params);

		switch($method)
		{
		case 'GET':
			return $this->httpGet($url, $params);
			break;
		case 'POST':
			return $this->httpPost($url, $params);
			break;
		}
	}

	public function setToken($token = null, $secret = null)
	{
		$params = func_get_args();
		$this->token = $token;
		$this->tokenSecret = $secret;
	}

	protected function encode_rfc3986($string)
	{
		return str_replace('+', ' ', str_replace('%7E', '~', rawurlencode(($string))));
	}

	protected function addOAuthHeaders(&$ch, $url, $oauthHeaders)
	{
		$_h = array('Expect:');
		$urlParts = parse_url($url);
		$oauth = 'Authorization: OAuth realm="' . $urlParts['path'] . '",';
		foreach($oauthHeaders as $name => $value)
		{
			$oauth .= $name.'="'.$value.'",';
		}
		$_h[] = substr($oauth, 0, -1);

		curl_setopt($ch, CURLOPT_HTTPHEADER, $_h);
	}

	protected function generateNonce()
	{
		if(isset($this->nonce)) 
			return $this->nonce;

		return md5(uniqid(rand(), true));
	}

	protected function generateSignature($method = null, $url = null, $params = null)
	{
		if(empty($method) || empty($url))
			return false;


		$concatenatedParams = '';
		foreach($params as $k => $v)
		{
			$v = $this->encode_rfc3986($v);
			$concatenatedParams .= "{$k}={$v}&";
		}
		$concatenatedParams = $this->encode_rfc3986(substr($concatenatedParams, 0, -1));

		$normalizedUrl = $this->encode_rfc3986($this->normalizeUrl($url));
		$method = $this->encode_rfc3986($method);

		$signatureBaseString = "{$method}&{$normalizedUrl}&{$concatenatedParams}";
		return $this->signString($signatureBaseString);
	}

	protected function httpGet($url, $params = null)
	{
		if(count($params['request']) > 0)
		{
			$url .= '?';
			foreach($params['request'] as $k => $v)
			{
				$url .= "{$k}={$v}&";
			}
			$url = substr($url, 0, -1);
		}
		$ch = curl_init($url);
		$this->addOAuthHeaders($ch, $url, $params['oauth']);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$resp = $this->curl->addCurl($ch);

		return $resp;
	}

	protected function httpPost($url, $params = null)
	{
		$ch = curl_init($url);
		$this->addOAuthHeaders($ch, $url, $params['oauth']);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params['request']));
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$resp = $this->curl->addCurl($ch);
		return $resp;
	}

	protected function normalizeUrl($url = null)
	{
		$urlParts = parse_url($url);

		if ( !isset($urlParts['port']) ) $urlParts['port'] = 80;

		$scheme = strtolower($urlParts['scheme']);
		$host = strtolower($urlParts['host']);
		$port = intval($urlParts['port']);

		$retval = "{$scheme}://{$host}";
		if($port > 0 && ($scheme === 'http' && $port !== 80) || ($scheme === 'https' && $port !== 443))
		{
			$retval .= ":{$port}";
		}
		$retval .= $urlParts['path'];
		if(!empty($urlParts['query']))
		{
			$retval .= "?{$urlParts['query']}";
		}

		return $retval;
	}

	protected function prepareParameters($method = null, $url = null, $params = null)
	{
		if(empty($method) || empty($url))
			return false;

		$oauth['oauth_consumer_key'] = $this->consumerKey;
		$oauth['oauth_token'] = $this->token;
		$oauth['oauth_nonce'] = $this->generateNonce();
		$oauth['oauth_timestamp'] = !isset($this->timestamp) ? time() : $this->timestamp; 
		$oauth['oauth_signature_method'] = $this->signatureMethod;
		$oauth['oauth_version'] = $this->version;

		// encoding
		array_walk($oauth, array($this, 'encode_rfc3986'));
		if(is_array($params))
			array_walk($params, array($this, 'encode_rfc3986'));
		$encodedParams = array_merge($oauth, (array)$params);

		// sorting
		ksort($encodedParams);

		// signing
		$oauth['oauth_signature'] = $this->encode_rfc3986($this->generateSignature($method, $url, $encodedParams));
		return array('request' => $params, 'oauth' => $oauth);
	}

	protected function signString($string = null)
	{
		$retval = false;
		switch($this->signatureMethod)
		{
		case 'HMAC-SHA1':
			$key = $this->encode_rfc3986($this->consumerSecret) . '&' . $this->encode_rfc3986($this->tokenSecret);
			$retval = base64_encode(hash_hmac('sha1', $string, $key, true));
			break;
		}

		return $retval;
	}

	public function __construct($consumerKey, $consumerSecret, $signatureMethod='HMAC-SHA1')
	{
		$this->consumerKey = $consumerKey;
		$this->consumerSecret = $consumerSecret;
		$this->signatureMethod = $signatureMethod;
		$this->curl = EpiCurl::getInstance();
	}
}

class EpiTwitter extends EpiOAuth
{
	const EPITWITTER_SIGNATURE_METHOD = 'HMAC-SHA1';
	protected $requestTokenUrl	= 'http://twitter.com/oauth/request_token';
	protected $accessTokenUrl = 'http://twitter.com/oauth/access_token';
	protected $authorizeUrl = 'http://twitter.com/oauth/authorize';
	protected $apiUrl = 'http://twitter.com';
	protected $searchUrl = 'http://search.twitter.com';

	public function __call($name, $params = null)
	{
		$parts = explode('_', $name);
		$method = strtoupper(array_shift($parts));
		$parts = implode('_', $parts);
		$path = '/' . preg_replace('/([A-Z]|[0-9])+/e', "'/'.strtolower($1)", $parts) . '.json';
		$args = NULL;

		if(!empty($params))
			$args = array_shift($params);

		if(preg_match('/^(search|trends)/', $parts))
		{
			$query = isset($args) ? http_build_query($args) : '';
			$url = "{$this->searchUrl}{$path}?{$query}";
			$ch = curl_init($url);
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

			return new EpiTwitterJson(EpiCurl::getInstance()->addCurl($ch));
		}

		return new EpiTwitterJson(call_user_func(array($this, 'httpRequest'), $method, "{$this->apiUrl}{$path}", $args));
	}

	public function __construct($consumer_key, $consumer_secret, $access_token, $access_token_secret)
	{
		$consumerKey	= $consumer_key;
		$consumerSecret = $consumer_secret;
		$oauthToken		= $access_token;
		$oauthTokenSecret = $access_token_secret;

		parent::__construct($consumerKey, $consumerSecret, self::EPITWITTER_SIGNATURE_METHOD);
		$this->setToken($oauthToken, $oauthTokenSecret);
	}
}

class EpiTwitterJson implements ArrayAccess, Countable, IteratorAggregate
{
	private $__resp;
	public function __construct($response)
	{
		$this->__resp = $response;
	}

	public function getIterator ()
	{
		return new ArrayIterator($this->response);
	}

	public function count ()
	{
		return count($this->response);
	}

	public function offsetSet($offset, $value)
	{
		$this->response[$offset] = $value;
	}

	public function offsetExists($offset)
	{
		return isset($this->response[$offset]);
	}

	public function offsetUnset($offset)
	{
		unset($this->response[$offset]);
	}

	public function offsetGet($offset)
	{
		return isset($this->response[$offset]) ? $this->response[$offset] : null;
	}

	public function __get($name)
	{
		$this->responseText = $this->__resp->data;
		$this->response = json_decode($this->responseText, 1);
		$obj = json_decode($this->responseText);

		foreach($obj as $k => $v)
		{
			$this->$k = $v;
		}

		if ( $name == '_result' )
		{
			return $obj;
		}

		return $this->$name;
	}

	public function __isset($name)
	{
		$value = self::__get($name);
		return empty($name);
	}
}

class EpiOAuthResponse
{
	private $__resp;

	public function __construct($resp)
	{
		$this->__resp = $resp;
	}

	public function __get($name)
	{
		if($this->__resp->code < 200 || $this->__resp->code > 299)
			return false;

		parse_str($this->__resp->data, $result);
		foreach($result as $k => $v)
		{
			$this->$k = $v;
		}

		if ( $name === '_result')
		{
			return $result;
		}

		return $result[$name];
	}
}

class EpiCurl
{
	const timeout = 3;
	static $inst = null;
	static $singleton = 0;
	private $mc;
	private $msgs;
	private $running;
	private $requests = array();
	private $responses = array();
	private $properties = array();

	function __construct()
	{
		if(self::$singleton == 0)
		{
			throw new Exception('This class cannot be instantiated by the new keyword. You must instantiate it using: $obj = EpiCurl::getInstance();');
		}

		$this->mc = curl_multi_init();
		$this->properties = array(
			'code' => CURLINFO_HTTP_CODE,
			'time' => CURLINFO_TOTAL_TIME,
			'length'=> CURLINFO_CONTENT_LENGTH_DOWNLOAD,
			'type' => CURLINFO_CONTENT_TYPE
		);
	}

	public function addCurl($ch)
	{
		$key = (string)$ch;
		$this->requests[$key] = $ch;

		$res = curl_multi_add_handle($this->mc, $ch);

		// (1)
		if($res === CURLM_OK || $res === CURLM_CALL_MULTI_PERFORM)
		{
			do {
				$mrc = curl_multi_exec($this->mc, $active);
			} while ($mrc === CURLM_CALL_MULTI_PERFORM);

			return new EpiCurlManager($key);
		}
		else
		{
			return $res;
		}
	}
		/*
call('statuses/friends_timeline');
search('search', array('q' => 'elliot'));
search('trends');
search('trends/current');
search('trends/daily');
search('trends/weekly');
call('statuses/public_timeline');
call('statuses/friends_timeline');
call('statuses/user_timeline');
call('statuses/show', array('id' => 1234));
call('direct_messages');
call('statuses/update', array('status' => 'If this tweet appears, oAuth is working!'));
call('statuses/destroy', array('id' => 1234));
call('users/show', array('id' => 'elliothaughin'));
call('statuses/friends', array('id' => 'elliothaughin'));
call('statuses/followers', array('id' => 'elliothaughin'));
call('direct_messages');
call('direct_messages/sent');
call('direct_messages/new', array('user' => 'jamierumbelow', 'text' => 'This is a library test. Ignore'));
call('direct_messages/destroy', array('id' => 123));
call('friendships/create', array('id' => 'elliothaughin'));
call('friendships/destroy', array('id' => 123));
call('friendships/exists', array('user_a' => 'elliothaughin', 'user_b' => 'jamierumbelow'));
call('account/verify_credentials');
call('account/rate_limit_status');
call('account/rate_limit_status');
call('account/update_delivery_device', array('device' => 'none'));
call('account/update_profile_colors', array('profile_text_color' => '666666'));
call('help/test');
		 */
	public function getResult($key = null)
	{
		if($key != null)
		{
			if(isset($this->responses[$key]))
			{
				return $this->responses[$key];
			}

			$running = null;
			do
			{
				$resp = curl_multi_exec($this->mc, $runningCurrent);
				if($running !== null && $runningCurrent != $running)
				{
					$this->storeResponses($key);
					if(isset($this->responses[$key]))
					{
						return $this->responses[$key];
					}
				}
				$running = $runningCurrent;
			}while($runningCurrent > 0);
		}

		return false;
	}

	private function storeResponses()
	{
		while($done = curl_multi_info_read($this->mc))
		{
			$key = (string)$done['handle'];
			$this->responses[$key]['data'] = curl_multi_getcontent($done['handle']);
			foreach($this->properties as $name => $const)
			{
				$this->responses[$key][$name] = curl_getinfo($done['handle'], $const);
				curl_multi_remove_handle($this->mc, $done['handle']);
			}
		}
	}

	static function getInstance()
	{
		if(self::$inst == null)
		{
			self::$singleton = 1;
			self::$inst = new EpiCurl();
		}

		return self::$inst;
	}
}

class EpiCurlManager
{
	private $key;
	private $epiCurl;

	function __construct($key)
	{
		$this->key = $key;
		$this->epiCurl = EpiCurl::getInstance();
	}

	function __get($name)
	{
		$responses = $this->epiCurl->getResult($this->key);
		return $responses[$name];
	}
}

class Twitter {
	private $_url_api	= 'http://twitter.com/';
	private $_url_api_search	= 'http://search.twitter.com/';
	private $_api_format		= 'json';

	private $_methods = array(
		'statuses/public_timeline'		=> array('http' => 'get',	'auth' => FALSE),
		'statuses/friends_timeline'		=> array('http' => 'get',	'auth' => TRUE),
		'statuses/user_timeline'		=> array('http' => 'get',	'auth' => FALSE),
		'statuses/mentions'		=> array('http' => 'get',	'auth' => TRUE),
		'statuses/show'	=> array('http' => 'get',	'auth' => FALSE),
		'statuses/update'		=> array('http' => 'post',	'auth' => TRUE),
		'statuses/destroy'		=> array('http' => 'post',	'auth' => TRUE),
		'users/show'	=> array('http' => 'get',	'auth' => FALSE),
		'statuses/friends'		=> array('http' => 'get',	'auth' => FALSE),
		'statuses/followers'	=> array('http' => 'get',	'auth' => TRUE),
		'direct_messages'		=> array('http' => 'get',	'auth' => TRUE),
		'direct_messages/sent'	=> array('http' => 'get',	'auth' => TRUE),
		'direct_messages/new'	=> array('http' => 'post',	'auth' => TRUE),
		'direct_messages/destroy'		=> array('http' => 'post',	'auth' => TRUE),
		'friendships/create'	=> array('http' => 'post',	'auth' => TRUE),
		'friendships/destroy'	=> array('http' => 'post',	'auth' => TRUE),
		'friendships/exists'	=> array('http' => 'get',	'auth' => TRUE),
		'account/verify_credentials'	=> array('http' => 'get',	'auth' => TRUE),
		'account/rate_limit_status'		=> array('http' => 'get',	'auth' => FALSE),
		'account/end_session'	=> array('http' => 'post',	'auth' => TRUE),
		'account/update_delivery_device'=> array('http' => 'post',	'auth' => TRUE),
		'account/update_profile_colors' => array('http' => 'post',	'auth' => TRUE),
		'account/update_profile'		=> array('http' => 'post',	'auth' => TRUE),
		'favorites'		=> array('http' => 'get',	'auth' => TRUE),
		'favorites/create'		=> array('http' => 'post',	'auth' => TRUE),
		'notifications/follow'	=> array('http' => 'post',	'auth' => TRUE),
		'notifications/leave'	=> array('http' => 'post',	'auth' => TRUE),
		'blocks/create'	=> array('http' => 'post',	'auth' => TRUE),
		'blocks/destroy'		=> array('http' => 'post',	'auth' => TRUE),
		'help/test'		=> array('http' => 'get',	'auth' => FALSE)
	);

	private $_conn;
	public $oauth;

	function __construct()
	{
		$this->_conn = new Twitter_Connection();
	}

	public function auth($username, $password)
	{
		$this->deauth();
		$this->_conn->auth($username, $password);
	}

	public function oauth($consumer_key, $consumer_secret, $access_token = NULL, $access_token_secret = NULL)
	{
		$this->deauth();
		$this->oauth = new EpiTwitter($consumer_key, $consumer_secret, $access_token, $access_token_secret);
		$this->oauth->setToken($access_token, $access_token_secret);

		if ( $access_token === NULL && $access_token_secret === NULL && !isset($_GET['oauth_token']) )
		{
			$url = $this->oauth->getAuthorizationUrl();

			header('Location: '.$url);
		}
		elseif ( $access_token === NULL && $access_token_secret === NULL && isset($_GET['oauth_token']) )
		{
			$access_token = $_GET['oauth_token'];
			$this->oauth->setToken($access_token);

			$info = $this->oauth->getAccessToken();
			$info = $info->_result;

			if ( !empty($info['oauth_token']) && !empty($info['oauth_token_secret']) )
			{
				$response = array(
					'access_token' => $info['oauth_token'],
					'access_token_secret' => $info['oauth_token_secret']
				);

				$this->oauth->setToken($response['access_token'], $response['access_token_secret']);

				return $response;
			}
		}

		return TRUE;
	}

	public function deauth()
	{
		$this->oauth = NULL;
		$this->_conn->deauth();
	}

	public function search($method, $params = array())
	{
		$url = $this->_url_api_search.$method.'.'.$this->_api_format;

		return $this->_conn->get($url, $params);
	}

	public function call($method, $params = array())
	{


		$http = 'get';
		$auth = FALSE;



		if ( isset($this->_methods[$method]) )
		{
			$http = $this->_methods[$method]['http'];
			$auth = $this->_methods[$method]['auth'];
		}

		if ( $auth === TRUE && ( $this->_conn->authed() || $this->oauth === NULL) )
		{

			return NULL;
		}

		if ( $this->oauth !== NULL )
		{
			$parts = explode('/', $method);

			if ( count($parts) > 1 )
			{
				$method_string = $http.'_'.$parts[0].ucfirst($parts[1]);
			}
			else
			{
				$method_string = $http.'_'.$parts[0];
			}

			$data = $this->oauth->$method_string($params);
			return $data->_result;
		}

		$url = $this->_url_api . $method . '.' .$this->_api_format;

		return $this->_conn->$http($url, $params);
	}
}

class Twitter_Connection {

	private $_curl		= NULL;
	private $_auth_method		= NULL;
	private $_auth_user	= NULL;
	private $_auth_pass	= NULL;

	function __construct()
	{
	}

	private function _init()
	{
		$this->_curl = curl_init();

		curl_setopt($this->_curl, CURLOPT_RETURNTRANSFER, TRUE);

		if ( $this->_auth_method == 'basic' )
		{
			curl_setopt($this->_curl, CURLOPT_USERPWD, "$this->_auth_user:$this->_auth_pass");
		}
	}

	public function authed()
	{
		if ( $this->_auth_method === NULL ) return FALSE;

		return TRUE;
	}

	public function auth($username, $password)
	{
		$this->deauth();

		$this->_auth_method = 'basic';
		$this->_auth_user	= $username;
		$this->_auth_pass	= $password;
	}

	public function deauth($auth_method = NULL)
	{
		if ( $auth_method == 'basic' || NULL )
		{
			$this->_auth_user	= NULL;
			$this->_auth_pass	= NULL;
		}

		$this->_auth_method	= NULL;
	}

	public function get($url, $params = array())
	{
		$this->_init();

		if ( is_array($params) && !empty($params) )
		{
			$url = $url . '?' . $this->_params_to_query($params);
		}

		curl_setopt($this->_curl, CURLOPT_URL, $url);

		return $this->deserialize(curl_exec($this->_curl));
	}

	public function post($url, $params = array())
	{
		$this->_init();

		if ( is_array($params) && !empty($params) )
		{
			curl_setopt($this->_curl, CURLOPT_POSTFIELDS, $this->_params_to_query($params));
		}

		curl_setopt($this->_curl, CURLOPT_POST, TRUE);
		curl_setopt($this->_curl, CURLOPT_URL, $url);

		return $this->deserialize(curl_exec($this->_curl));
	}

	private function _params_to_query($params)
	{
		if ( !is_array($params) || empty($params) )
		{
			return '';
		}

		$query = '';

		foreach	( $params as $key => $value )
		{
			$query .= $key . '=' . $value . '&';
		}

		return substr($query, 0, strlen($query) - 1);;
	}

	private function deserialize($result)
	{
		return json_decode($result);
	}
}

function processFollowers($followers) {
	foreach ($followers as $follower) {
		echo "Twitter ID: {$follower['screen_name']}\n";
		echo "Name: {$follower['name']}\n";
		echo "Website: {$follower['url']}\n";
		echo "Am I following this person?: ".($follower['following'] ? "Yes\n" : "No\n");
		echo "Friends: {$follower['friends_count']}\n";
		echo "Followers: {$follower['followers_count']}\n";		
		echo "Description: {$follower['description']}\n\n";
	}
}

?>
