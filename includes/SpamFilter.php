<?php
namespace FlowThread;

use MediaWiki\MediaWikiServices;
use ObjectCache;
use Wikimedia\AtEase\AtEase;

class SpamFilter {

	/**
	 * Baidu API
	 */
	private const BAIDU_API_URL = 'https://aip.baidubce.com/rest/2.0/solution/v1/text_censor/v2/user_defined';
	/**
	 * Baidu access token API
	 */
    private const BAIDU_ACCESS_TOKEN_URL = 'https://aip.baidubce.com/oauth/2.0/token';

	/**
	 * Validate if a regular expression is valid
	 */
	private static function validateRegex($regex) {
		AtEase::suppressWarnings();
		$ok = preg_match($regex, '');
		AtEase::restoreWarnings();

		if ($ok === false) {
			return false;
		}

		return true;
	}

	/**
	 * Parse a line in spam blacklist
	 */
	private static function parseLine($line) {
		$line = trim(preg_replace('/#.*$/', '', $line)); // Remove comments and trim space
		if (!$line) {
			// The line does not contain a regular expression
			return null;
		}

		// Extract regex and options from the result
		$result = null;
		preg_match('/^(.*?)(?:\s*<([^<>]*)>)?$/', $line, $result);
		@list($full, $regex, $opts) = $result;

		if (!$line) {
			// Cannot contain only options
			return null;
		}

		if (!$opts) {
			// Default value
			$opts = '';
		}

		// Must be a valid regex
		// This can also prevent problems when we joining the regex using |
		if (!self::validateRegex('/' . $regex . '/')) {
			// Abort for invalid regex
			return null;
		}

		return array(
			'regex' => $regex,
			'opt' => $opts,
		);
	}

	/**
	 * Parse option part in blacklist line (enclosed in <>)
	 */
	private static function parseOptions($opts) {
		$options = array();
		$segments = explode('|', $opts);
		foreach ($segments as $opt) {
			// Extract key=value pair
			$exploded = explode('=', $opt, 2);
			$key = $exploded[0];
			$value = isset($exploded[1]) ? $exploded[1] : '';

			switch ($key) {
			case 'replace':
				// Replace the text instead of marking as spam
				$options['replace'] = $value;
				break;
			default:
				$services = MediaWikiServices::getInstance();
				if (in_array($key, $services->getPermissionManager()->getAllPermissions())) {
					// If the name is a user right
					if (isset($options['right'])) {
						$options['right'][] = $key;
					} else {
						$options['right'] = array($key);
					}
				} else if (in_array($key, $services->getUserGroupManager()->listAllGroups())) {
					// If the name is a user group
					if (isset($options['group'])) {
						$options['group'][] = $key;
					} else {
						$options['group'] = array($key);
					}
				}
			}
		}
		return $options;
	}

	/**
	 * Parse whole spam blacklist
	 */
	private static function parseLines($lines) {
		$batches = array();
		foreach ($lines as $line) {
			$parsed = self::parseLine($line);
			if ($parsed) {
				if (isset($batches[$parsed['opt']])) {
					// Concatenate regexes to speed up
					$batches[$parsed['opt']] .= '|' . $parsed['regex'];
				} else {
					$batches[$parsed['opt']] = $parsed['regex'];
				}
			}
		}
		$ret = array();
		foreach ($batches as $opt => $regex) {
			$ret[] = array(
				'/' . $regex . '/iu',
				self::parseOptions($opt),
			);
		}
		return $ret;
	}

	private static function getBlackList() {
		$cache = MediaWikiServices::getInstance()->getMainWANObjectCache();
		return $cache->getWithSetCallback(
			ObjectCache::getLocalClusterInstance()->makeKey('flowthread', 'spamblacklist'),
			60,
			function () {
				$source = wfMessage('flowthread-blacklist')->inContentLanguage();
				if ($source->isDisabled()) {
					return array();
				}
				$lines = explode("\n", $source->text());
				return self::parseLines($lines);
			}
		);
	}

	/**
	 * Get baidu access token
	 */
	private static function getBaiduAccessToken($refresh = false) {
		global $wgFlowThreadConfig;
		$cache = MediaWikiServices::getInstance()->getMainWANObjectCache();
		
		$apiKey = $wgFlowThreadConfig['BaiduApiKey'];
		$secretKey = $wgFlowThreadConfig['BaiduSecretKey'];
		$tokenExpire = $wgFlowThreadConfig['BaiduAccessTokenExpire'];

		$res =  $cache->getWithSetCallback(
			ObjectCache::getLocalClusterInstance()->makeKey('flowthread', 'baidu_accesstoken'),
			$tokenExpire,
			function () use ($apiKey, $secretKey) {
				if(!$apiKey || !$secretKey) {
					return null;
				}

				$url = self::BAIDU_ACCESS_TOKEN_URL . '?grant_type=client_credentials&client_id=' . urlencode($apiKey) . '&client_secret=' . urlencode($secretKey);
				self::debug('百度AI获取access_token:' . $url);
				$curl = curl_init();
        		curl_setopt_array($curl, array(
            		CURLOPT_URL => $url,
            		CURLOPT_TIMEOUT => 30,
            		CURLOPT_RETURNTRANSFER => true,
            		CURLOPT_SSL_VERIFYPEER  => false,
            		CURLOPT_SSL_VERIFYHOST  => false,
            		CURLOPT_CUSTOMREQUEST => 'POST',
            		CURLOPT_HTTPHEADER => array(
                		'Content-Type: application/json',
                		'Accept: application/json'
            		),
        		));
				curl_setopt($curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
				$response = curl_exec($curl);
				$httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
				$curlError = curl_error($curl);
        		curl_close($curl);

				if($curlError) {
					self::debug('获取百度AccessToken请求失败: ' . $curlError);
					return null;
				}

				if ($httpCode != 200) {
					self::debug('获取百度AccessTokenHTTP错误: ' . $httpCode);
            		return null;
        		}

				if ($response) {
					self::debug('获取百度access_token' . $response);
					$data = json_decode($response, true);
                    if (isset($data['access_token'])) {
                        return $data['access_token'];
                    }
				}
				self::debug('获取百度access_token失败');

				return null;
			}
		);
		if(!$res && !$refresh) {
			// clear cache
			$cache->delete(ObjectCache::getLocalClusterInstance()->makeKey('flowthread', 'baidu_accesstoken'));
			return self::getBaiduAccessToken(true);
		}
		else {
			return $res;
		}
	}

	/**
	 * Check Text with baidu
	 * 
	 * @param string $text
	 * @return bool return spam result. true: spam, false: not spam
	 */
	private static function checkWithBaidu($text, $poster, $ip) {
		global $wgFlowThreadConfig;
		$ErrorDefault = isset($wgFlowThreadConfig['BaiduErrorDefault']) ? $wgFlowThreadConfig['BaiduErrorDefault'] : true;
		$BaiduCheckLevel = $wgFlowThreadConfig['BaiduCheckLevel'];
		// if not use baidu check (not include 1 and 2)
		if ($BaiduCheckLevel < 1) {
			self::debug('百度审核等级：' . $BaiduCheckLevel);
			return false;
		}
		$accessToken = self::getBaiduAccessToken();
		if (!$accessToken) {
			$cache = MediaWikiServices::getInstance()->getMainWANObjectCache();
			// clear cache
			$cache->delete(ObjectCache::getLocalClusterInstance()->makeKey('flowthread', 'baidu_accesstoken'));
			self::debug('百度AccessToken：' . $accessToken);
			return false;
		}

		$url = self::BAIDU_API_URL . '?access_token=' . urlencode($accessToken);

		$postData = array(
            'text' => $text,
			'userId' => $poster->getName(),
			'userIp' => $ip
        );
		$curl = curl_init();
		curl_setopt_array($curl, array(
            CURLOPT_URL => $url,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER  => false,
            CURLOPT_SSL_VERIFYHOST  => false,
            CURLOPT_CUSTOMREQUEST => 'POST',
            
            CURLOPT_POSTFIELDS => http_build_query($postData),
    
            CURLOPT_HTTPHEADER => array(
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json'
            ),

        ));
		curl_setopt($curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        $response = curl_exec($curl);
		$httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		$curlError = curl_error($curl);
        curl_close($curl);

		if($curlError) {
			self::debug('百度内容审核请求失败: ' . $curlError);
			return $ErrorDefault;
		}

		if ($httpCode != 200) {
			self::debug('百度内容审核HTTP错误: ' . $httpCode);
            return $ErrorDefault; // HTTP错误，允许通过
        }

		$result = json_decode($response, true);
		if (!$result) {
			self::debug('百度内容审核响应解析失败');
            return $ErrorDefault; // 解析失败，允许通过
        }

		if (isset($result['conclusionType'])) {
			$conclusionType = $result['conclusionType'];
			if($conclusionType == 1){
				return false;
			}
			// if conclusionType is 3 and BaiduCheckLevel is 2, return true
			if($conclusionType == 3 && $BaiduCheckLevel == 2){
				return false;
			}
			self::debug('百度内容审核结果: ' . $conclusionType);
			return true;
		}

		return $ErrorDefault;
	}

	public static function validate($text, $poster, $wikitext, $ip) {
		$blacklist = self::getBlackList();
		$spammed = false;
		$ret = array(
			'good' => true,
		);

		foreach ($blacklist as $line) {
			list($regex, $opt) = $line;
			if (preg_match($regex, $text)) {
				if (isset($opt['group'])) {
					// When user is in the allowed group list, we skip this rule
					if (count(array_intersect($opt['group'], $poster->getGroups()))) {
						continue;
					}
				}

				if (isset($opt['right'])) {
					// Right-based control
					foreach ($opt['right'] as $item) {
						if ($poster->isAllowed($item)) {
							continue 2;
						}
					}
				}

				if (isset($opt['replace'])) {
					$replaceText = $opt['replace'];
					if ($wikitext) {
						$replaceText = '<nowiki>' . $replaceText . '</nowiki>';
					}
					// Do text replace instead of moving into spam
					$text = preg_replace($regex, $replaceText, $text);
					continue;
				}

				// Mark as bad
				$ret['good'] = false;
			}
		}
		if($ret['good']) {
			$spammed = self::checkWithBaidu($text, $poster, $ip);
			self::debug($spammed ? '百度内容审核结果: true' : '百度内容审核结果: false');
			$ret['good'] = !$spammed;
		}

		$ret['text'] = $text;
		return $ret;
	}

	public static function sanitize($html) {
		return preg_replace('/position(?:\/\*[^*]*\*+([^\/*][^*]*\*+)*\/|\s)*:(?:\/\*[^*]*\*+([^\/*][^*]*\*+)*\/|\s)*fixed/i', '', $html);
	}

	private static function debug($text) {
		$file = false;
		if ($file) {
			$text = '[' . date('Y-m-d H:i:s') . '] ' . $text;
			file_put_contents(dirname(__FILE__) . '/spamfilter.log', $text . "\n", FILE_APPEND);
		}
		else {
			wfDebugLog('FlowThread', $text);
		}
	}
}
