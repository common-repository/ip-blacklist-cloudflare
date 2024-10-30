<?php

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Access denied.' );
}

/**
 * Class CFIP_SiteSettings
 *
 * Handles setting up the admin settings menus
 * and screens.
 *
 */
class CFIP_SiteSettings
{

	/**
	 * CFIP_SiteSettings constructor.
	 *
	 * Runs on instantiation.
	 *
	 */
	public function __construct()
	{
        $helperFunctions = new CFIP_Helpers();
		$this->siteBaseDomain = $helperFunctions->parseBaseDomainFromURL(get_site_url())['domain'];

		$cfip_settings = get_option('cfip_settings');
		$this->settings = is_array($cfip_settings) ? $cfip_settings : array();

        /**
         * Overwrite API authentication with credentials from official Cloudflare plugin
         * if they exist and the plugin is active
         */
        if($this->isCloudflarePluginActive()) {
            $cf_plugin_email = get_option('cloudflare_api_email');
            $cf_plugin_key = get_option('cloudflare_api_key');

            // Only use if both are present
            if ($cf_plugin_key && $cf_plugin_email) {
                $this->settings['cf_email'] = $cf_plugin_email;
                $this->settings['cf_key'] = $cf_plugin_key;
            }
        }

	}

    /**
     * Checks to see if the official Cloudflare plugin is active.
     *
     * Method below is used in place of is_plugin_active because this can happen at any
     * time during site load whereas is_plugin_active only happens after admin_init
     *
     * @return bool
     */
    public function isCloudflarePluginActive(){
        $active_plugins_basenames = get_option( 'active_plugins' );
        foreach ( $active_plugins_basenames as $plugin_basename ) {
            if ( false !== strpos( $plugin_basename, '/cloudflare.php' ) ) {
                return true;
            }
        }

        return false;
	}

    /**
     * Checks to see if the official Cloudflare plugin is active and credentials are set.
     * @return array|bool
     */
    public function areCloudflarePluginCredentialsSet(){
	    // Only use credentials if Cloudflare plugin is active, even if the values are in the DB
        if(!$this->isCloudflarePluginActive())
            return false;

		if(!empty(get_option('cloudflare_api_key', null)) && !empty(get_option('cloudflare_api_email', null)))
			return array('cf_key'=>get_option('cloudflare_api_key', null),'cf_email'=>get_option('cloudflare_api_email', null));

		return false;
	}

    /**
     * Checks to see if Cloudflare credentials are set either through the official
     * Cloudflare plugin or through this plugin manually.
     *
     * @return array|bool
     */
    public function areCredentialsSet(){
        // First, get API email and key from CloudFlare plugin settings, if available.
        if($use_cloudflare_plugin_credentials = $this->areCloudflarePluginCredentialsSet()){
            $cf_key = $use_cloudflare_plugin_credentials['cf_key'];
            $cf_email = $use_cloudflare_plugin_credentials['cf_email'];
            $cf_source = 'cf_plugin';
        } else if($use_cloudflare_ip_plugin_credentials = (!empty($this->settings['cf_key']) && !empty($this->settings['cf_email']))){
            $cf_key = $this->settings['cf_key'];
            $cf_email = $this->settings['cf_email'];
            $cf_source = 'manual';
        } else {
            return false;
        }

        return array('cf key' => $cf_key, 'cf_email' => $cf_email, 'source' => $cf_source);
    }

    public function isLoggingEnabled(){
        return array_key_exists('enable_logging', $this->settings) && $this->settings['enable_logging']=='on';
    }

	/**
	 * Registers the network admin menu page.
	 *
	 */
	public function addSiteMenu()
	{
		add_menu_page(
			'IP Blacklist for Cloudflare',
			'IP Blacklist for Cloudflare',
			'manage_options',
			'cfip-menu',
			array($this, 'addSiteMenuCB'),
			plugin_dir_url(plugin_dir_path(__FILE__)).'assets/media/cf-facebook-card.png'
		);
	}

	/**
	 * Callback for add_menu_page to display the
	 * settings page.
	 *
	 */
	public function addSiteMenuCB()
	{
		$this->displaySiteSettingsMenu();
	}

	/**
	 * Include the settings menu template.
	 *
	 */
	public function displaySiteSettingsMenu()
	{
		include_once(plugin_dir_path(plugin_dir_path(__FILE__)).'views/SiteSettingsView.php');
	}

	/**
	 * Verify nonce on form submit, then update settings.
	 *
	 */
	public function verifyNonce() {
		if ( isset($_POST['submit']) ) {

			// Bail if nonce not set.
			if ( !isset( $_POST['cfip_settings_nonce'] ) )
				return false;

			// Verify nonce.
			if ( @!wp_verify_nonce($_POST['cfip_settings_nonce'], 'cfip_settings_nonce') )
				return false;

			return $this->updateSettings();
		}
		return false;
	}

	/**
	 * Update option 'cfip_settings' with $_POST data.
	 *
	 * @return bool
	 */
	public function updateSettings() {
		// Load current options if available
	    $settings = $this->settings;

		if (isset($_POST['cfip_settings_nonce'])) {

			/**
             * Cloudflare Credentials
             * First, check if new values are posted
             * Second, check if there are already values set in the DB and that the
             * Third, set to nothing if both fail
             **/
            $settings['cf_email'] = isset($_POST['cf_email']) ? sanitize_text_field($_POST['cf_email']) : (array_key_exists('cf_email', $settings) ? $settings['cf_email'] : '');
			$settings['cf_key'] = isset($_POST['cf_key']) ? sanitize_text_field($_POST['cf_key']) : (array_key_exists('cf_key', $settings) ? $settings['cf_key'] : '');
			$settings['banned_usernames'] = isset($_POST['banned_usernames']) ? sanitize_text_field($_POST['banned_usernames']) : (array_key_exists('banned_usernames', $settings) ? $settings['banned_usernames'] : '');
			$settings['zone_id'] = isset($_POST['zone_id']) ? sanitize_text_field($_POST['zone_id']) : (array_key_exists('zone_id', $settings) ? $settings['zone_id'] : '');

			/**
             * Handle checkboxes differently since they don't send POST values
             * This is ok though because it is proper to ask people to re-enable blacklist and logging settings
             * if they refresh their credentials
             **/
            $settings['enable_ip_blacklist'] = isset($_POST['enable_ip_blacklist']) ? sanitize_text_field($_POST['enable_ip_blacklist']) : '';
            $settings['enable_logging'] = isset($_POST['enable_logging']) ? sanitize_text_field($_POST['enable_logging']) : '';

			if( update_option('cfip_settings', $settings) )
				return true;

		}

		return false;

	}

}