<?php
/**
 * Class Auth0MemberExtension
 * 
 * @author Arno Bor
 * @package auth0
 */
class Auth0MemberExtension extends DataExtension
{

    private static $db = array(
        'Auth0Id' => "Varchar(191)",
        'Auth0LastUpdate' =>"Datetime",
    );

    public function updateCMSFields(FieldList $fields)
    {
        
        // Remove the automatically-generated field.
        $fields->removeFieldFromTab('Root', 'Auth0Id');
        $fields->removeFieldFromTab('Root', 'Auth0LastUpdate');
        
        $tab = new Tab('Auth0');

        $authId = new TextField('Auth0Id', 'Id');
        $authDate = new DatetimeField('Auth0LastUpdate', "Last Updated");

        $tab->Fields()->add($authId);
        $tab->Fields()->add($authDate);
        
        $fields->addFieldToTab('Root', $tab);

        return $fields;
    }

}
