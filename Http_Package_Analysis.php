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
        return $result;
    }


}