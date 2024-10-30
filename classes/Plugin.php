<?php

if (!defined('ABSPATH')) {
    die('Access denied.');
}

/**
 * Plugin Class
 */
class CFIP_Blacklist
{

    /**
     * The settings class.
     *
     * @var CFIP_Settings
     */
    public $siteSettings;

    /**
     * The plugin settings.
     *
     * @var mixed
     */
    public $settings;

    /**
     * The API class.
     *
     * @var CFIP_CloudflareAPIController
     */
    public $API;

    /**
     * Admin stylesheet file.
     *
     */
    public $adminStyle;

    /**
     * Admin javascript file.
     *
     */
    public $adminScript;

    /**
     * CFIP_Blacklist constructor.
     *
     * Initialize plugin properties/hooks.
     *
     */
    public function __construct ()
    {
        $this->siteSettings = new CFIP_SiteSettings();
        $this->API = new CFIP_CloudflareAPIController();
        $this->settings = get_site_option('cfip_settings');

        $this->adminStyle = plugins_url('ip-blacklist-for-cloudflare/assets/css/admin.css', 'ip-blacklist-for-cloudflare.php');
        $this->adminScript = plugins_url('ip-blacklist-for-cloudflare/assets/js/admin.js', 'ip-blacklist-for-cloudflare.php');

        // Hooks
        add_action('admin_enqueue_scripts', array ($this, 'adminEnqueueScripts'), 40, 1);

        // IP Blacklist
        add_action('wp_authenticate', array ($this, 'checkUserLoginName'), 10, 1);

        // AJAX requests
        add_action('wp_ajax_cfip_unblacklist_ip', array ($this, 'ajaxUnblacklistIP'));
        add_action('wp_ajax_cfip_clearlog', array ($this, 'ajaxClearLog'));
	    add_action('wp_ajax_cfip_loadlog', array ($this, 'ajaxLoadLog'));

        // Single Site Settings Screen
        add_action('admin_menu', array($this->siteSettings, 'addSiteMenu'));
        add_action('admin_menu', array($this->siteSettings, 'verifyNonce'));

        // Add 'Settings' link to plugin page
        //add_filter( 'plugin_action_links_'.plugin_basename( __FILE__ ), array ($this, 'cfip_add_action_links'), 10, 5);
    }

    /**
     * Enqueue admin scripts and stylesheets.
     *
     * @param $hook string
     */
    public function adminEnqueueScripts ($hook)
    {
        // Only enqueue on appropriate admin screen.
        if ($hook !== 'toplevel_page_cfip-menu')
            return;

        wp_enqueue_style('cfip_admin_style', $this->adminStyle, array(),CFIP_PLUGIN_VERSION);
        wp_enqueue_script('cfip_admin_script', $this->adminScript, array ('jquery'),CFIP_PLUGIN_VERSION);

        // If Cloudflare plugin is active, inherit styles from their plugin for consistent styles
        if($this->isCloudflarePluginActive()) {
            wp_enqueue_style('cf-corecss', CFIP_MAIN_CLOUDFLARE_PLUGIN_DIR.'/stylesheets/cf.core.css');
            wp_enqueue_style('cf-componentscss', CFIP_MAIN_CLOUDFLARE_PLUGIN_DIR.'/stylesheets/components.css');
            wp_enqueue_style('cf-hackscss', CFIP_MAIN_CLOUDFLARE_PLUGIN_DIR.'/stylesheets/hacks.css');
        }
    }

    /**
     * Add Links to main WP plugin page
     */
    /*public function cfip_add_action_links( $actions ) {
        $custom_actions = array(
            'settings' => sprintf( '<a href="%s">%s</a>', admin_url( 'admin.php?page=cfip-menu' ), 'Settings' )
        );

        // add the links to the front of the actions list
        return array_merge( $custom_actions, $actions );
    }*/

    /**
     * Check if official Cloudflare Plugin is installed and active
     */
    public function isCloudflarePluginActive(){
        return is_plugin_active( 'cloudflare/cloudflare.php' );
    }
    
    /**
     * Check if login name has been blacklisted.
     *
     * @param $username string
     * @return void
     */
    public function checkUserLoginName ($username)
    {
        // If IP Blacklisting is disabled, bail.
        if (!($this->getSetting('enable_ip_blacklist') == 'on'))
            return;

        $banned_usernames = array_map('trim', explode(',', $this->getSetting('banned_usernames')));
        if (in_array($username, $banned_usernames)) {
            $this->blacklistIPAddress();
        }
    }

    /**
     * Blacklist IP in CloudFlare via API call.
     *
     *
     * @param $ip
     * @return array|mixed|object
     */
    public function singleSiteBlacklistIP( $ip ){
        $zone_id = $this->API->getZoneId( get_site_url() );

        if(!$zone_id)
            return false;

        return array($zone_id => $this->API->blacklistIP( $zone_id, $ip ));
    }

    /**
     * Add user's IP address to site option and blacklist it in Cloudflare.
     *
     * @return void
     */
    public function blacklistIPAddress ()
    {
        // Get user's IP address.
        $ip = $this->getUserIPAddress();

        // If an IP address was retrieved, add to site option along with zone/request data and blacklist in Cloudflare.
        if ($ip) {
            $results = $this->singleSiteBlacklistIP( $ip );

            $ip_data = array(
                $ip => array(
                    'zones' => array()
                )
            );

            $updateBannedIPs = false;
            foreach ($results as $zone_id => $result) {
                if(!empty($result->errors)){
                    /**
                     * A delay exists (~5-10 seconds) after an IP has been added to the blacklist on Cloudflare
                     * and before it takes effect to the user trying to access the site.
                     *
                     * In these cases we handle API requests that are considered 'duplicates'/ error code: 10009
                     */
                    if($result->errors[0]->code==10009){
                        if ($this->siteSettings->isLoggingEnabled()) {
                            $this->log("IP already blocked. Skipping...");
                        }
                    }

                    continue;
                }

                $ip_data[$ip]['zones'][$zone_id]['request_id'] = $result->result->id;
                $updateBannedIPs = true;
            }

            if($updateBannedIPs)
                $this->updateBannedIPs($ip_data);
        }
    }

    /**
     * Get a user's IP address.
     *
     * @return string | bool
     */
    public function getUserIPAddress ()
    {
        foreach (array ('HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR') as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $IP) {
                    $IP = trim($IP);
                    if (filter_var($IP, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $IP;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get banned IP addresses from site option.
     * (found in wp_sitemeta)
     *
     * @return array
     */
    public function getBannedIPs ()
    {
        return (get_site_option('cfip_banned_addresses') ?: array ());
    }

    /**
     * Update site option with IP Address to ban (if it doesn't already exist).
     *
     * @param $ip_data array
     */
    public function updateBannedIPs ($ip_data)
    {
        $banned_IPs = $this->getBannedIPs();
        foreach ($ip_data as $ip => $data) {
            $banned_IPs[$ip] = $data;
            update_site_option('cfip_banned_addresses', $banned_IPs);
        }
    }

    /**
     * Remove $ip from blacklisted IPs in site option after unblocking
     * in Cloudflare API.
     *
     * @param $ip
     */
    public function removeBannedIP ($ip)
    {
        $banned_IPs = $this->getBannedIPs();
        if (isset($banned_IPs[$ip]))
            unset($banned_IPs[$ip]);

        update_site_option('cfip_banned_addresses', $banned_IPs);
    }

    /**
     * Remove an IP address from Cloudflare firewall rules.
     *
     */
    public function ajaxUnblacklistIP ()
    {
        $response = array (
            'result' => '',
            'errors' => array ()
        );

        if (!isset($_POST['ip_address']) || !$_POST['ip_address']) {
            $response['errors'][] = array ('error' => 'No IP address provided.');
            wp_die(json_encode($response));
        }

        $ip_address = preg_replace(array ('/\s{2,}/', '/[\t\n]/'), '', sanitize_text_field($_POST['ip_address']));
        $response['ip'] = $ip_address;

        $banned_IPs = $this->getBannedIPs();
        foreach ($banned_IPs as $ip => $data) {
            if ($ip == $ip_address) {
                foreach ($data['zones'] as $zone_id => $zone_data) {
                	if( !$zone_id )
                		continue;

                    $request_id = $zone_data['request_id'];
                    if( !$request_id )
                    	continue;
                    
                    $r = $this->API->deleteBlacklistedIP($zone_id, $request_id);
                    if (!$r->success && $r->errors) {
                        foreach ($r->errors as $error){
                        	if( !in_array($error->code, array(1003, 7000)) )
	                            $response['errors'][] = array ($error->code => $error->message);
                        }
                    }
                }
            }
        }

        if (!$response['errors']) {
            $this->removeBannedIP($ip_address);
            $response['result'] = 'success';
        }

        wp_die(json_encode($response));
    }

	/**
	 * Load/refresh log via AJAX when log tab is opened.
	 *
	 */
    public function ajaxLoadLog ()
    {
    	$response = array('log' => array());
	    $cfip_log = get_site_option('cfip_log')?:array();
	    if( $cfip_log ){
		    foreach( $cfip_log as $entry ){
		    	ob_start();
			    print_r(PHP_EOL);
		    	print_r($entry);
		    	$response['log'][] = ob_get_clean();
		    }
	    }

	    wp_die(json_encode($response));
    }

	/**
	 * Clear log via AJAX.
	 *
	 */
    public function ajaxClearLog ()
    {
        $response = array ();
        if (!isset($_POST['clear_log']) || !$_POST['clear_log']) {
            $response['error'] = 'An error occurred.';
            wp_die(json_encode($response));
        }

        if (!update_site_option('cfip_log', array ())) {
            $response['error'] = array ('error' => 'Failed to clear log.');
            wp_die(json_encode($response));
        }

        $response['result'] = 'success';
        wp_die(json_encode($response));
    }

    /**
     * Function to log events in a site option.
     *
     * @param $message
     */
    public function log ($message)
    {
        if ($this->siteSettings->isLoggingEnabled()){
            $log = get_site_option('cfip_log') ?: array();
            $log[] = $message;
            update_site_option('cfip_log', $log);
        }
    }

    /**
     * Helper function to get plugin settings.
     *
     * @param $setting
     * @return string|array|null
     */
    public function getSetting ($setting)
    {
        return $this->settings[$setting];
    }
}