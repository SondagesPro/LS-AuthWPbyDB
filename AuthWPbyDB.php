<?php
/**
 * Authentification via WordPress Plugin for LimeSurvey
 *
 * @author Denis Chenu <denis@sondages.pro>
 * @copyright 2014 Denis Chenu <http://sondages.pro>
 * @copyright 2014 Bruce Mahillet de Komet <http://jevaluemaformation.com>
 * @license GPL v3
 * @version 1.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

class AuthWPbyDB extends AuthPluginBase
{
    protected $storage = 'DbStorage';
    
    static protected $description = 'A plugin to authenticate user via WordPress DB.';
    static protected $name = 'WordPress DB Authentification';

    protected $settings = array(
        'authwp_dbhost' => array(
            'type' => 'string',
            'label' => 'WordPress DB Host (default to LimeSurvey DB Host)'
        ),
        'authwp_dbport' => array(
            'type' => 'string',
            'label' => 'WordPress DB Port (default to LimeSurvey DB Port or 3306 id name or host is define)'
        ),
        'authwp_dbname' => array(
            'type' => 'string',
            'label' => 'WordPress DB Name  (default to LimeSurvey DB Name)'
        ),
        'authwp_dbuser' => array(
            'type' => 'string',
            'label' => 'WordPress DB User (default to LimeSurvey DB User)'
        ),
        'authwp_dbpassword' => array(
            'type' => 'string',
            'label' => 'WordPress DB User password (default to LimeSurvey DB User)'
        ),
        'authwp_dbprefix' => array(
            'type' => 'string',
            'label' => 'WordPress DB prefix',
            'default' => 'wp_'
        ),
        'authwp_default' => array(
            'type' => 'checkbox',
            'label' => 'Check to make default authentication method'
        ),
        'authwp_autocreate' => array(
            'type' => 'checkbox',
            'label' => 'Auto create user.',
            'default' => true
        ),
    );

    protected $sWpLoad = false;

    public function __construct(PluginManager $manager, $id) {
        parent::__construct($manager, $id);
        /**
         * Here you should handle subscribing to the events your plugin will handle
         */
        $this->subscribe('beforeLogin');
        $this->subscribe('newLoginForm');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLoginFormSubmit');
        $this->subscribe('beforeActivate');
    }

    public function beforeActivate()
    {
        $oEvent = $this->getEvent();
        // Get configuration settings:
        if($this->testWpDb())
        {
            $oEvent->set('success', true);
        }else{
            $oEvent->set('success', false);
            $oEvent->set('message',"Unable to conect to WordPress DB, please verify the connection parameters");
        }
    }

    public function beforeLogin()
    {
        $oEvent = $this->getEvent();
        if ($this->testWpDb() && $this->get('authwp_default'))
        {
            $this->getEvent()->set('default', get_class($this));
        }
    }

    public function newLoginForm()
    {
        $this->getEvent()->getContent($this)
             ->addContent(CHtml::tag('li', array(), "<label for='user'>"  . gT("Username") . "</label><input name='user' id='user' type='text' size='40' maxlength='40' value='' />"))
             ->addContent(CHtml::tag('li', array(), "<label for='password'>"  . gT("Password") . "</label><input name='password' id='password' type='password' size='40' maxlength='40' value='' />"));
    }

    public function afterLoginFormSubmit()
    {
        // Allways (trying to reset password if user exist in DB ????)
        $request = $this->api->getRequest();
        if ($request->getIsPostRequest()) {
            $this->setUsername( $request->getPost('user'));
            $this->setPassword($request->getPost('password'));
        }
    }

    public function newUserSession()
    {
        $sUserName = $this->getUserName();
        $sUserPass = $this->getPassword();

        $aWpUser=$this->getWpDbUser($sUserName,$sUserPass);
        if(!$aWpUser){
            $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
            return;
        }
        $oUser = $this->api->getUserByName($sUserName);
        if (is_null($oUser) && $this->get('authwp_autocreate'))
        {
            $oUser=new User;
            $oUser->users_name=$aWpUser['user_login'];
            $oUser->full_name=$aWpUser['display_name'];
            $oUser->password=substr(md5(rand()),0,20);;
            $oUser->parent_id=1;
            $oUser->lang='auto';
            $oUser->email=$aWpUser['user_email'];
            if ($oUser->save())
            {
                // TODO by plugin settings
                if((int)$aWpUser['user_level']>=9){
                    $aPermission=Array(
                        'superadmin' => array('read'=>true),
                    );
                }else{
                    $aPermission=Array(
                        'surveys' => array('create'=>true,'import'=>true,'export'=>true),
                        'template' => array('read'=>true),
                        'labelsets' => array('read'=>true,'export'=>true),
                        'participantpanel' => array('create'=>true,'read'=>true,'update'=>true,'delete'=>true),
                    );
                }
                $permission=new Permission;
                $permission->setPermissions($oUser->uid, 0, 'global', $aPermission, true);

                // read again user from newly created entry
                $this->setAuthSuccess($oUser);
                return;
            }else{
                $this->setAuthFailure("DB error");
                return;
            }
        }
        elseif($oUser)// Invalid user
        {
                $this->setAuthSuccess($oUser);
                return;
        }
        else{
            $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
            return;
        }
    }

    /**
    * Validate user by username/password from WordPress
    * @param string $sUserName : the user name
    * @param string $sUserPass : the user pass
    * return array : User information
    **/
    private function getWpDbUser($sUserName,$sUserPass)
    {
        if($this->testWpDb())
        {
            $aUser = Yii::app()->wpdb->createCommand()
                                    ->select('user_login,user_pass,user_nicename,user_email,display_name,ul.meta_value as user_level')
                                    ->from('{{users}}')
                                    ->leftJoin('{{usermeta}} ul', 'ID = ul.user_id AND ul.meta_key="wp_user_level"')
                                    ->andWhere("user_login = :user_login")
                                    ->bindParam(':user_login',$sUserName)
                                    ->queryRow();
            if(!$aUser)
                return;
            //Yii::import('plugins.AuthWPbyAPI.third_party.phpass.PasswordHash');
            require_once dirname(__FILE__).'/third_party/phpass/PasswordHash.php';// DIRECTORY_SEPARATOR not needed
            $oHasher = new PasswordHash(8, TRUE);
            $bCheck = $oHasher->CheckPassword($sUserPass, $aUser['user_pass']);
            if($bCheck)
                return $aUser;
            else
                return;
        }
        else
        {
            return; // Invalid settings
        }
    }
    /**
    * Add the db from plugin configuration in new Yii db
    **/
    private function addWpDb()
    {
        $bExist=Yii::app()->getComponent('wpdb',false);
        if($bExist)// If already exist 
            return;
        $sWpDbHost      = $this->get('authwp_dbhost');
        $sWpDbPort      = $this->get('authwp_dbport');
        $sWpDbName      = $this->get('authwp_dbname');
        $sWpDbUser      = $this->get('authwp_dbuser');
        $sWpDbPassword  = $this->get('authwp_dbpassword');
        $sWpDbPrefix    = $this->get('authwp_dbprefix');
        $sWpDbCharset   = "utf8";
        if($sWpDbHost || $sWpDbPort || $sWpDbName){
            if(!$sWpDbPort)
                $sWpDbPort="3306";
            $sConnectionString="mysql:host={$sWpDbHost};port={$sWpDbPort};dbname={$sWpDbName}";
        }else{
            $sConnectionString=Yii::app()->db->connectionString;
        }
        if(!$sWpDbUser)
            $sWpDbUser=Yii::app()->db->username;
        if(!$sWpDbPassword)
            $sWpDbPassword=Yii::app()->db->password;

        $wpdb = Yii::createComponent(array(
           'class' => 'CDbConnection',
             'connectionString'=>$sConnectionString,
                'username'=>$sWpDbUser,
                'password'=> $sWpDbPassword,
                'charset'=>$sWpDbCharset,
                'emulatePrepare' => true,
                'tablePrefix' => $sWpDbPrefix,
        ));
        Yii::app()->setComponent('wpdb', $wpdb);

    }
    private function testWpDb()
    {
        $this->addWpDb();
        $sWpDbPrefix = $this->get('authwp_dbprefix');
        // Test the connexion and return false if NOT
        if(!in_array($sWpDbPrefix.'options',Yii::app()->wpdb->schema->getTableNames())){
            return false;
        }else{
            return true;
        }
    }

}
