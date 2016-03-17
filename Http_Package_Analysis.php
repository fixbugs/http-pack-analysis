<?php

/**
 * HTTP Package analysis Library
 *
 * goitt:"Every is possible, easy to analysis http package."
 *
 *
 */
class Http_Package_Analysis{

    /**
     * HTTP server info.
     */
    protected $httpServers = array();

    protected $result = array();

    public function __construct(array $server=null){
        $this->setHttpServer($server);
    }

    /**
     * Set http server
     * @param array $server server array
     * @return bool
     */
    public function setHttpServer($server=null){
        $this->httpServers = array();
        if(!is_array($server) || !count($server)){
            $this->httpServers = $_SERVER;
        }else{
            $this->httpServers = $server;
        }
        return true;
    }

    /**
     * get http server info
     * @return array
     */
    public function getHttpServer(){
        return $this->httpServers;
    }

    /**
     * Analysis manage
     */
    public function analysisResult(){
        $this->_urlInfoAnalysis();
        $this->_iPInfoAnalysis();
        $this->_timeInfoAnalysis();
        $this->_userAgentInfoAnalysis();
        return $this->result;
    }

    /**
     * Analysis server info for url and sth.
     */
    private function _urlInfoAnalysis(){
        $this->result['url'] = $this->httpServers['HTTP_HOST'].$this->httpServers['REQUEST_URI'];
        $this->result['domain'] = self::getUrlDomain($this->result['url']);
        $this->result['domain_md5'] = md5($this->result['domain']);
        $this->result['refer'] = isset($this->httpServers['HTTP_REFERER']) ? $this->httpServers['HTTP_REFERER']:'';
        $this->result['now_page_url'] = $this->result['url'];
        $this->result['now_url_md5'] = md5($this->result['url']);
        $this->result['pre_page_url'] = $this->result['refer'];
        $this->result['pre_url_md5'] = $this->result['refer'] ? md5($this->result['refer']):'';
    }

    /**
     * Analysis time info form server.
     */
    private function _timeInfoAnalysis(){
        $this->result['create_time'] = isset($this->httpServers['REQUEST_TIME']) ? $this->httpServers['REQUEST_TIME']:time();
    }

    /**
     * Analysis ip info form server.
     */
    private function _iPInfoAnalysis(){
        $ip = $this->_getClientIp();
        $this->result['user_ip'] = $ip;
        $this->result['ip_md5'] = md5($ip);
        $city_info = self::getCityInfoByIp($ip);
        $this->result = array_merge($this->result, $city_info);
    }

    private function _userAgentInfoAnalysis(){
        $this->result['user_agent'] = isset($this->httpServers['HTTP_USER_AGENT']) ? $this->httpServers['HTTP_USER_AGENT']:'';
        $this->result['user_agent_md5'] = $this->result['user_agent'] ? md5($this->result['user_agent']):'';
    }

    /**
     * Get city info by ip from taobao ip library without IP checked
     * @param string $ip IP
     * @return array
     */
    static public function getCityInfoByIp($ip){
        $url = 'http://ip.taobao.com/service/getIpInfo.php?ip='.$ip;
        $res = self::curl_get($url);
        $default_result = array(
            'country' => '未知ip',
            'country' => '0',
            'area' => '',
            'area_id' => '',
            'region' => '',
            'region_id' => '',
            'city' => '',
            'city_id'  => '',
            'county' => '',
            'county_id' => '',
            'isp' => '',
            'isp_id' => '',
            'ip' => $ip,
        );
        if($res['result']){
            $result = json_decode($res['result'], true);
        }else{
            return $default_result;
        }
        if(!$result['data']){
            return $default_result;
        }
        return $result['data'];
    }

    /**
     * curl get for url
     * @param string $url url
     * @param array $data params need to send
     * @param array $header Http request header
     * @param int $timeout Max request for connect
     * @param int $port Port for request
     * @return array
     */
    static public function curl_get($url, $data = array(), $header = array(), $timeout = 5, $port = 80){
        $start_time = time();
        $req_data = $data;
        $ch = curl_init();
        if (!empty($data)) {
            $data = is_array($data) ? http_build_query($data) : $data;
            $url .= (strpos($url, '?') ? '&' : "?") . $data;
        }
        $setheader = array();
        if(isset($header['host'])){
            if(preg_match('/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/', $header['host'])){
                $ip = $header['host'];
                $host = get_url_domain($url);
                if($host){
                    $setheader = array("Host:".$host);
                    $url = preg_replace("/{$host}/", $ip, $url, 1);
                }
            }else{
                $setheader = array("Host:".$header['host']);
            }
            unset($header['host']);
        }
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_POST, 0);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        !empty($setheader) && curl_setopt($ch, CURLOPT_HTTPHEADER, $setheader);

        $result = array();
        $result['result'] = curl_exec($ch);
        curl_close($ch);
        return $result;
    }

    /**
     * Get client info from httpServers
     * @param bool $checkProxy Is need to check proxy
     * @return string
     */
    private function _getClientIp($checkProxy = true)
    {
        $ip = '127.0.0.1';
        if($checkProxy && isset($this->httpServers['HTTP_CLIENT_IP'])){
            $ip = $this->httpServers['HTTP_CLIENT_IP'];
        }elseif($checkProxy && isset($this->httpServers['HTTP_X_FORWARDED_FOR'])){
            $ip = $this->httpServers['HTTP_X_FORWARDED_FOR'];
        }elseif(!empty($this->httpServers['REMOTE_ADDR'])){
            $ip = $this->httpServers['REMOTE_ADDR'];
        }
        return $ip;
    }

    /**
     * Get url domain
     * @param string $url url
     * @return string or false
     */
    static public function getUrlDomain($url){
        if(preg_match('/^(https?:\/\/)?([a-z0-9.-]+)(\/.*)?$/i', $url,$matches)){
            return $matches[2];
        }
        return false;
    }

}