<?php
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

class XmlrpcProtector_Action extends Typecho_Widget implements Widget_Interface_Do
{
    public function action()
    {
        // 检查是否是生成token的请求
        if ($this->request->get('generate_token')) {
            echo $this->generateToken();
            return;
        }
        
        // 尝试获取插件配置，如果失败则使用默认配置
        try {
            // 尝试获取插件配置，如果失败则使用默认配置
        try {
            $options = Helper::options()->plugin('XmlrpcProtector');
        } catch (Exception $e) {
            $options = (object) [
                'token' => '',
                'limit' => 30,
                'whitelist' => '',
                'redirectOnInvalidToken' => 0
            ];
        }
        } catch (Exception $e) {
            // 如果无法获取插件配置，则使用默认配置
            $options = (object) [
                'token' => $this->generateToken(),
                'limit' => 30,
                'whitelist' => '',
                'redirectOnInvalidToken' => 0
            ];
        }
        $token = $this->request->get('token');
        $clientIp = $this->getClientIp();

        // 检查安全 token
        if ($token !== $options->token) {
            $this->log($clientIp, 'INVALID_TOKEN');
            
            // 根据设置决定是显示错误信息还是跳转到127.0.0.1
            if ($options->redirectOnInvalidToken) {
                $this->response->redirect('http://127.0.0.1');
                return;
            } else {
                throw new Typecho_Widget_Exception('Invalid XML-RPC endpoint');
            }
        }

        // 检查白名单
        if (!empty($options->whitelist)) {
            $whitelist = explode("\n", $options->whitelist);
            $whitelist = array_map('trim', $whitelist);
            if (!in_array($clientIp, $whitelist)) {
                $this->log($clientIp, 'NOT_IN_WHITELIST');
                throw new Typecho_Widget_Exception('Access denied: IP not allowed');
            }
        }

        // 限流：一分钟内限制次数
        $this->checkRateLimit($clientIp, intval($options->limit));

        // 转发到原始 xmlrpc
        Typecho_Widget::widget('Widget_XmlRpc')->action();
    }

    /**
     * 获取当前XML-RPC权限状态
     */
    public function getPermissionStatus() 
    {
        // 尝试获取插件配置，如果失败则使用默认配置
        try {
            $options = Helper::options()->plugin('XmlrpcProtector');
        } catch (Exception $e) {
            $options = (object) [
                'token' => '',
                'limit' => 30,
                'whitelist' => '',
                'redirectOnInvalidToken' => 0
            ];
        }
        
        $status = array(
            'token' => $options->token ? '已设置' : '未设置',
            'rate_limit' => is_numeric($options->limit) && $options->limit > 0 ? intval($options->limit) . '次/分钟' : '未设置',
            'whitelist' => !empty($options->whitelist) ? 
                array_values(array_filter(array_map('trim', explode("\n", $options->whitelist)), 'strlen')) : '未设置',
            'redirect_on_invalid_token' => $options->redirectOnInvalidToken ? '跳转到127.0.0.1' : '显示错误信息',
            'current_time' => date('Y-m-d H:i:s'),
            'active_connections' => $this->getActiveConnectionsCount(),
        );
        
        // 检查缓存文件是否存在且可读写
        $cacheFile = __TYPECHO_ROOT_DIR__ . '/usr/plugins/XmlrpcProtector/cache.json';
        if (file_exists($cacheFile)) {
            $status['cache_status'] = '存在且可' . (is_writable($cacheFile) ? '写' : '读');
        } else {
            $status['cache_status'] = '不存在';
        }
        
        return $status;
    }
    
    private function getActiveConnectionsCount() 
    {
        $cacheFile = __TYPECHO_ROOT_DIR__ . '/usr/plugins/XmlrpcProtector/cache.json';
        if (!file_exists($cacheFile)) {
            return 0;
        }
        
        $cacheData = json_decode(file_get_contents($cacheFile), true);
        $currentTime = time();
        $activeCount = 0;
        
        foreach ($cacheData as $record) {
            if ($currentTime - $record['time'] < 60) {
                $activeCount++;
            }
        }
        
        return $activeCount;
    }

    private function getClientIp()
    {
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function checkRateLimit($ip, $limit)
    {
        $cacheFile = __TYPECHO_ROOT_DIR__ . '/usr/plugins/XmlrpcProtector/cache.json';
        $cacheKey = 'xmlrpc_rate_' . md5($ip);
        
        // 读取缓存文件
        $cacheData = [];
        if (file_exists($cacheFile)) {
            $cacheData = json_decode(file_get_contents($cacheFile), true);
        }
        
        $currentTime = time();
        
        // 获取当前IP的记录
        if (!isset($cacheData[$cacheKey])) {
            $record = ['count' => 1, 'time' => $currentTime];
        } else {
            $record = $cacheData[$cacheKey];
            // 检查是否在1分钟内
            if ($currentTime - $record['time'] < 60) {
                $record['count']++;
                if ($record['count'] > $limit) {
                    $this->log($ip, 'RATE_LIMIT_EXCEEDED');
                    throw new Typecho_Widget_Exception('Too many XML-RPC requests, try later');
                }
            } else {
                // 超过1分钟，重置计数
                $record = ['count' => 1, 'time' => $currentTime];
            }
        }
        
        // 更新记录
        $cacheData[$cacheKey] = $record;
        
        // 清理1分钟前的记录
        foreach ($cacheData as $key => $value) {
            if ($currentTime - $value['time'] >= 60) {
                unset($cacheData[$key]);
            }
        }
        
        // 写入缓存文件
        file_put_contents($cacheFile, json_encode($cacheData));
    }

    private function log($ip, $status)
    {
        $logFile = __TYPECHO_ROOT_DIR__ . '/usr/plugins/XmlrpcProtector/xmlrpc_log.txt';
        $entry = date('Y-m-d H:i:s') . " | IP: {$ip} | Status: {$status}\n";
        file_put_contents($logFile, $entry, FILE_APPEND);
    }

    /**
     * 生成安全Token
     */
    public function generateToken($length = 32)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }
        return $randomString;
    }
}