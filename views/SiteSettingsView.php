<?php
$siteSettings = new CFIP_SiteSettings();
$cfip_settings = $siteSettings->settings;
$credentials = $siteSettings->areCredentialsSet();

// The plugin settings. Add new sections/fields accordingly.
$settings = array(
	'Cloudflare Credentials' => array(
        'fields' => array(
            array(
                'name' => 'cf_email',
                'type' => 'text',
                'title' => 'Email Address',
                'description' => '',
                'value' => ($credentials && array_key_exists('cf_email', $credentials))? $credentials['cf_email'] : ''
            ),
            array(
                'name' => 'cf_key',
                'type' => 'text',
                'title' => 'API Key',
                'description' => '',
                'value' => ($credentials && array_key_exists('cf_key', $credentials)) ? $credentials['cf_key'] : ''
            )
        )
	),
	'Blacklist IPs' => array(
		'fields' => array(
			array(
				'name' => 'enable_ip_blacklist',
				'type' => 'checkbox',
				'title' => 'Enable IP Blacklisting?',
                'description' => ''
			),
			array(
				'name' => 'banned_usernames',
				'type' => 'textarea',
				'title' => 'Banned Usernames',
				'description' => 'Comma-separated string, e.g. admin, administrator'
			),
            array(
                'name' => 'enable_logging',
                'type' => 'checkbox',
                'title' => 'Enable Logging?',
                'description' => ''
            )
		)
	)
);

// Populate options array with banned IP addresses.
$banned_IPs = get_option('cfip_banned_addresses') ?: array();
$banned_IPs_list = array();

if($banned_IPs){
    foreach( $banned_IPs as $ip => $data ){
        $banned_IPs_list[$ip] = $ip;
    }
}

$blacklist_ip_type = count($banned_IPs_list)==0 ? 'span' : 'select';

$blacklist_ip_settings_array = array(
    'name' => 'blacklisted_ips',
    'type' => $blacklist_ip_type,
    'title' => 'Blacklisted IPs',
    'description' => 'IPs currently blocked from the site'
);

if(count($banned_IPs_list)==0){
    $blacklist_ip_settings_array['value'] = 'No IPs currently blacklisted.';
} else {
    $blacklist_ip_settings_array['options'] = $banned_IPs_list;
}

$settings['Blacklist IPs']['fields'][] = $blacklist_ip_settings_array;

?>
<ul class="tabs clearfix" data-tabgroup="first-tab-group">
    <li><a href="#tab1" class="active">Settings</a></li>
    <li><a href="#tab2" class="log_tab">Log</a></li>
</ul>
<section id="first-tab-group" class="tabgroup">
    <div class="tab-panel" id="tab1">
        <h1 class="cf-heading cf-heading--1"><span>Settings</span> (<?php echo $siteSettings->siteBaseDomain; ?>)</h1>
        <form name="cfip_settings" method="post" action="">
            <table>
                <tbody>
                    <?php
                    foreach( $settings as $section=>$fields ){
                        /**
                        * Only display full form if credentials are set
                        */
                        if($section=='Cloudflare Credentials' || ($section!=='Cloudflare Credentials' && $credentials)) {
                            ?>
                            <tr class="tr-section-title">
                                <td><h2 class="cf-heading cf-heading--2"><?php echo $section; ?></h2></td>
                                <?php
                                if($section=='Cloudflare Credentials' && !$credentials){
                                    echo '<span class="cf-card__footer_message">Please manually set credentials below or install and configure the <a href="http://wordpress.org/plugins/cloudflare/" target="_blank">official Cloudflare plugin</a> to continue.</span>';
                                }
                                ?>
                            </tr>

                            <?php
                            // If Cloudflare credentials are filled out from Cloudflare plugin
                            if($section=='Cloudflare Credentials' && $this->isCloudflarePluginActive() && ($credentials && $credentials['source']=='cf_plugin')) {
                                $cloudflare_admin_url = admin_url()."options-general.php?page=cloudflare";
                                ?>
                                <tr>
                                    <td>Credentials imported from <a href="<?php echo $cloudflare_admin_url; ?>">Cloudflare</a> plugin.</td>
                                </tr>
                                <?php continue;
                            }


                            foreach ($fields['fields'] as $field => $data) {
                                if ($data['type'] == 'select') {
                                    ?>
                                    <tr>
                                        <td><h3 class="cf-card__title"><label for="<?php echo $data['name']; ?>"><?php echo $data['title']; ?></label></h3>
                                        </td>
                                        <td>
                                            <select id="<?php echo $data['name']; ?>"
                                                    name="<?php echo $data['name']; ?>">
                                                <?php
                                                if ($banned_IPs) {
                                                    foreach ($banned_IPs_list as $name => $val) {
                                                        ?>
                                                        <option name="<?php echo $name; ?>"
                                                                value="<?php echo $val; ?>"><?php echo $val; ?></option>
                                                        <?php
                                                    }
                                                }
                                                ?>
                                            </select>
                                        </td>
                                    </tr>
                                    <?php
                                } else if ($data['type'] == 'textarea') {
                                    ?>
                                    <tr>
                                        <td><h3 class="cf-card__title"><label
                                                    for="<?php echo $data['name']; ?>"><?php echo $data['title']; ?>
                                                </label></h3>
                                            <?php
                                            if (isset($data['description']) && $data['description']) {
                                                ?>
                                                <span
                                                    class="cf-card__footer_message"><?php echo $data['description']; ?></span>
                                                <?php
                                            }
                                            ?>
                                        </td>
                                        <td><textarea id="<?php echo $data['name']; ?>"
                                                      name="<?php echo $data['name']; ?>" rows="4"
                                                      cols="50"><?php echo(array_key_exists($data['name'], $cfip_settings) ? $cfip_settings[$data['name']] : ''); ?></textarea>
                                        </td>
                                    </tr>
                                    <?php
                                } else if ($data['type'] == 'checkbox') {
                                    ?>
                                    <tr>
                                        <td><h3 class="cf-card__title"><label
                                                    for="<?php echo $data['name']; ?>"><?php echo $data['title']; ?>
                                                </label></h3>
                                            <?php
                                            if (isset($data['description']) && $data['description']) {
                                                ?>
                                                <span
                                                    class="cf-card__footer_message"><?php echo $data['description']; ?></span>
                                                <?php
                                            }
                                            ?>
                                        </td>
                                        <td><input id="<?php echo $data['name']; ?>" type="<?php echo $data['type']; ?>"
                                                   name="<?php echo $data['name']; ?>" <?php echo(array_key_exists($data['name'], $cfip_settings) && $cfip_settings[$data['name']] == 'on' ? 'checked' : ''); ?>>
                                        </td>
                                    </tr>
                                    <?php
                                } else if ($data['type'] == 'span') {
                                    ?>
                                    <tr>
                                        <td><h3 class="cf-card__title"><label
                                                    for="<?php echo $data['name']; ?>"><?php echo $data['title']; ?>
                                                </label></h3>
                                            <?php
                                            if (isset($data['description']) && $data['description']) {
                                                ?>
                                                <span
                                                    class="cf-card__footer_message"><?php echo $data['description']; ?></span>
                                                <?php
                                            }
                                            ?>
                                        </td>
                                        <td><span
                                                id="<?php echo $data['name']; ?>"><?php echo(array_key_exists($data['name'], $cfip_settings) && $cfip_settings[$data['name']] ? $cfip_settings[$data['name']] : ($data['value'] ?: '')); ?></span>
                                        </td>
                                    </tr>
                                    <?php
                                } else {
                                    ?>
                                    <tr>
                                        <td><h3 class="cf-card__title"><label
                                                    for="<?php echo $data['name']; ?>"><?php echo $data['title']; ?>
                                                </label></h3>
                                            <?php
                                            if (isset($data['description']) && $data['description']) {
                                                ?>
                                                <span
                                                    class="cf-card__footer_message"><?php echo $data['description']; ?></span>
                                                <?php
                                            }
                                            ?>
                                        </td>
                                        <td><input id="<?php echo $data['name']; ?>" type="<?php echo $data['type']; ?>"
                                                   name="<?php echo $data['name']; ?>"
                                                   value="<?php echo(array_key_exists($data['name'], $cfip_settings) && $cfip_settings[$data['name']] ? $cfip_settings[$data['name']] : ($data['value'] ?: '')); ?>">
                                        </td>
                                    </tr>
                                    <?php
                                }
                            }
                        }
                    }
                    ?>
                </tbody>
            </table>
            <?php wp_nonce_field('cfip_settings_nonce', 'cfip_settings_nonce'); ?>
            <?php submit_button('Save Changes', 'cf-btn cf-btn--primary'); ?>
        </form>
    </div>
    <div class="tab-panel" id="tab2">
        <h1 class="cf-heading cf-heading--1"><span>Log</span></h1>
        <?php
        if(!$siteSettings->isLoggingEnabled()) {
            ?>
        <span class="cf-card__footer_message">Logging is currently disabled. To start logging, enable checkbox on settings tab.</span>
            <?php
        }
            ?>
        <div id="log_screen">
            <pre></pre>
        </div>
        <button id="clear_log_button" class="button button-primary cf-btn cf-btn--primary">Clear Log</button>
        <div id="cfip_ajax_res_clearlog"></div>
    </div>
</section>
<?php
