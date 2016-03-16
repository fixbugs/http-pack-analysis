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

    public function analysisResult(){
        $this->_urlInfoAnalysis();
        return $this->result;
    }

    /**
     * Analysis server info for url and sth.
     */
    private function _urlInfoAnalysis(){
        $this->result['url'] = $this->httpServers['HTTP_HOST'].$this->httpServers['REQUEST_URI'];
        $this->result['refer'] = isset($this->httpServers['HTTP_REFERER']) ? $this->httpServers['HTTP_REFERER']:'';
        $this->result['now_page_url'] = $this->result['url'];
        $this->result['now_url_md5'] = md5($this->result['url']);
        $this->result['pre_page_url'] = $this->result['refer'];
        $this->result['pre_url_md5'] = $this->result['refer'] ? md5($this->result['refer']):'';
    }


}