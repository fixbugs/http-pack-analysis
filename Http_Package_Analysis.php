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

    /**
     * Analysis result store array
     */
    protected $result = array();

    /**
     * Analysis init info with server input or self $_SERVER
     */
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
        $this->_userEquipInfoAnalysis();
        return $this->result;
    }

    /**
     * Analysis server info for url and sth.
     */
    private function _urlInfoAnalysis(){
        $uri = $this->httpServers['REQUEST_URI'];
        $http = ( isset($this->httpServers['HTTPS']) && $this->httpServers['HTTPS'] !='off' ) ? 'https://':'http://';
        $port = $this->httpServers['SERVER_PORT']==80 ? '':':'.$this->httpServers['SERVER_PORT'];

        $this->result['url'] = $http . $this->httpServers['HTTP_HOST']. $port . $uri;

        $this->result['domain'] = self::getUrlDomain($this->result['url']);
        $this->result['domain_md5'] = md5($this->result['domain']);
        $this->result['refer'] = isset($this->httpServers['HTTP_REFERER']) ? $this->httpServers['HTTP_REFERER']:'';
        $this->result['refer_domain'] = $this->result['refer'] ? self::getUrlDomain($this->result['refer']):'';
        $this->result['now_page_url'] = $this->result['url'];
        $this->result['now_url_md5'] = md5($this->result['url']);
        $this->result['pre_page_url'] = $this->result['refer'];
        $this->result['pre_url_md5'] = $this->result['refer'] ? md5($this->result['refer']):'';
        $this->result['request_method'] = $this->httpServers['REQUEST_METHOD'];
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

    /**
     * Analysis user agent.
     */
    private function _userAgentInfoAnalysis(){
        $this->result['user_agent'] = isset($this->httpServers['HTTP_USER_AGENT']) ? $this->httpServers['HTTP_USER_AGENT']:'';
        $this->result['user_agent_md5'] = $this->result['user_agent'] ? md5($this->result['user_agent']):'';
    }

    /**
     * Analysis user equipment from server.
     */
    private function _userEquipInfoAnalysis(){
        $equipment_info = self::getServerEquipmentInfo($this->httpServers);
        $this->result['equipment'] = $equipment_info['equipment'] ? $equipment_info['equipment']:'';
        $this->result['platform'] = $equipment_info['equipment_os'] ? $equipment_info['equipment_os']:'';
        $this->result['equipment_type'] = $equipment_info['equipment_type'] ? $equipment_info['equipment_type']:'';
        $this->result['user_browser'] = $equipment_info['equipment_browser'] ? $equipment_info['equipment_browser']:'';
    }

    /**
     * get server equipment info by SERVER.
     * @param array $server $_SERVER
     * @return array
     */
    static public function getServerEquipmentInfo($server){
        require_once('Mobile_Detect.php');
        $result = array();
        $detect = new Mobile_Detect($server);
        $is_mobile = $detect->isMobile();
        if($is_mobile){
            $mobileDetectRules = $detect->getMobileDetectionRules();
            $tmp_arr = array();
            foreach($mobileDetectRules as $k=>$v){
                if($detect->is($k)){
                    $tmp_arr[] = $k;
                }
            }
            $result['equipment_type'] = 'tablet';
            $result['equipment'] = $tmp_arr[0];
            $result['equipment_os'] = $tmp_arr[1];
            $result['equipment_browser'] = $tmp_arr[2];
        }else{
            require_once('PC_User_Agent.php');
            $pc_user_agent = new PC_User_Agent($server);
            $result['equipment_type'] = 'pc';
            $browsers = $pc_user_agent->getBrowsers();
            foreach($browsers as $k=>$v){
                if($pc_user_agent->is($k)){
                    $browser = $k;
                    break;
                }
            }
            $result['equipment_browser'] = $browser ? $browser:'';
            $systems_rules = $pc_user_agent->getOperatingSystems();
            foreach($systems_rules as $k=>$v){
                if($pc_user_agent->is($k)){
                    $system = $k;
                    break;
                }
            }
            $result['equipment_os'] = $system ? $system:'';
            $result['equipment'] = '';
        }
        return $result;
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
            'city_en' => '',
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
        require_once('StringToPY.php');
        $stringtopy_class = new StringToPY();
        $result['data']['city_en'] = $stringtopy_class->encode($result['data']['city']);
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