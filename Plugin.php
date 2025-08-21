<?php
if (!defined('__TYPECHO_ROOT_DIR__')) exit;

/**
 * Typecho XML-RPC 安全防护插件
 *
 * 功能：
 * 1. 修改 XML-RPC 入口地址（支持安全 token）
 * 2. 添加频率限制（IP 限流）
 * 3. 权限控制（仅允许白名单 IP / 用户）
 * 4. 请求日志记录（文件存储）
 *
 * @package XmlrpcProtector
 * @author Hans J. Han
 * @version 1.0.0
 * @link https://www.hansjack.com
 */
class XmlrpcProtector_Plugin implements Typecho_Plugin_Interface
{
    public static function activate()
    {
        Helper::addAction('xmlrpc', 'XmlrpcProtector_Action');
        return _t('XML-RPC 安全防护插件已启用，请在设置中配置安全参数。');
    }

    public static function deactivate()
    {
        Helper::removeAction('xmlrpc');
    }

    public static function config(Typecho_Widget_Helper_Form $form)
    {
        // 尝试获取现有插件配置，如果不存在则使用默认值
        $defaultToken = '';
        try {
            $pluginOptions = Helper::options()->plugin('XmlrpcProtector');
            $defaultToken = $pluginOptions->token ?? '';
        } catch (Exception $e) {
            // 如果无法获取插件配置，则稍后生成新的token
        }
        
        // 如果默认token为空，则生成新的
        if (empty($defaultToken)) {
            $defaultToken = Typecho_Widget::widget('XmlrpcProtector_Action')->generateToken();
        }
        
        $token = new Typecho_Widget_Helper_Form_Element_Text(
            'token', NULL, $defaultToken,
            _t('安全 Token'),
            _t('插件会将 XML-RPC 地址改为 action/xmlrpc?token=xxxx，防止被随意扫描')
        );
        $form->addInput($token);

        $limit = new Typecho_Widget_Helper_Form_Element_Text(
            'limit', NULL, '30',
            _t('频率限制（次/分钟）'),
            _t('每个 IP 在一分钟内最多请求次数，超过会被拦截')
        );
        $form->addInput($limit);

        $whitelist = new Typecho_Widget_Helper_Form_Element_Textarea(
            'whitelist', NULL, '',
            _t('IP 白名单'),
            _t('允许访问的 IP 列表，一行一个，不填则不启用')
        );
        $form->addInput($whitelist);
        
        // 添加token错误时跳转到127.0.0.1的选项
        $redirectOption = new Typecho_Widget_Helper_Form_Element_Radio(
            'redirectOnInvalidToken', 
            array(
                '0' => _t('显示错误信息'),
                '1' => _t('跳转到127.0.0.1')
            ), 
            '0', 
            _t('Token验证失败时的处理方式'),
            _t('当用户访问XML-RPC接口但token不正确时的处理方式')
        );
        $form->addInput($redirectOption);
        
        // 显示当前配置信息和保护措施
        try {
            $options = Helper::options()->plugin('XmlrpcProtector');
            // 获取权限状态信息
            $status = Typecho_Widget::widget('XmlrpcProtector_Action')->getPermissionStatus();
            
            echo '<div id="xmlrpc-protection-details" style="margin: 1em 0; padding: 1em; border: 1px solid #ddd; background: #f8f8f8;">';
            echo '<h3>XML-RPC 保护措施详情</h3>';
            
            echo '<ul style="list-style: none; padding: 0;">';
            echo '<li style="margin: 0.5em 0;"><strong>当前时间:</strong> ' . (isset($status['current_time']) ? $status['current_time'] : '未知') . '</li>';
            echo '<li style="margin: 0.5em 0;"><strong>活动连接数:</strong> ' . (isset($status['active_connections']) ? $status['active_connections'] : '未知') . '</li>';
            echo '<li style="margin: 0.5em 0;"><strong>缓存文件状态:</strong> ' . (isset($status['cache_status']) ? $status['cache_status'] : '未知') . '</li>';
            echo '</ul>';
            
            echo '<h4>已启用的保护措施:</h4>';
            echo '<ul style="list-style: none; padding: 0;">';
            echo '<li style="margin: 0.5em 0;">✅ Token 验证</li>';
            if (!empty($options->limit) && intval($options->limit) > 0) {
                echo '<li style="margin: 0.5em 0;">✅ 频率限制 (' . intval($options->limit) . ' 次/分钟)</li>';
            } else {
                echo '<li style="margin: 0.5em 0;">❌ 频率限制 (未设置)</li>';
            }
            
            if (!empty($options->whitelist)) {
                echo '<li style="margin: 0.5em 0;">✅ IP 白名单</li>';
            } else {
                echo '<li style="margin: 0.5em 0;">❌ IP 白名单 (未设置)</li>';
            }
            
            if ($options->redirectOnInvalidToken) {
                echo '<li style="margin: 0.5em 0;">✅ Token 验证失败跳转</li>';
            } else {
                echo '<li style="margin: 0.5em 0;">✅ Token 验证失败显示错误</li>';
            }
            echo '</ul>';
            
            // 根据是否开启重写功能显示正确的访问地址
            $siteUrl = Helper::options()->siteUrl;
            $rewriteEnabled = Helper::options()->rewrite;
            if ($rewriteEnabled) {
                $xmlrpcUrl = $siteUrl . 'action/xmlrpc?token=' . htmlspecialchars($options->token);
            } else {
                $xmlrpcUrl = $siteUrl . 'index.php/action/xmlrpc?token=' . htmlspecialchars($options->token);
            }
            
            echo '<h4>XML-RPC 访问地址:</h4>';
            echo '<p><code>' . $xmlrpcUrl . '</code></p>';
            echo '<p><small>当前URL重写状态: ' . ($rewriteEnabled ? '已启用' : '未启用') . '</small></p>';
            
            echo '</div>';
        } catch (Exception $e) {
            // 静默处理异常，不影响主要配置功能
        }
    }

    public static function personalConfig(Typecho_Widget_Helper_Form $form) 
    {
        // 个人配置页面不需要插入额外信息
    }
}