<?php
require_once 'Http_Package_Analysis.php';
$http_ana_cls = new Http_Package_Analysis();
var_dump($http_ana_cls->analysisResult());
var_dump($http_ana_cls->getCityInfoByIp('61.183.251.3'));