<?php

namespace DirectLease\Auth0;

use SilverStripe\Security\MemberAuthenticator\MemberLoginForm as SilverStripeMemberLoginForm;
use SilverStripe\View\Requirements;


class LoginForm extends SilverStripeMemberLoginForm {

    public function __construct(
        $controller,
        $authenticatorClass,
        $name,
        $fields = null,
        $actions = null,
        $checkCurrentUser = true
    ) {
        parent::__construct($controller, $authenticatorClass, $name, $fields, $actions, $checkCurrentUser);
        $auth0_client_id = $this->getConfigSetting('client_id', 'Auth0 client id');
        $auth0_domain = $this->getConfigSetting('domain', 'Auth0 domain');

        Requirements::javascript("https://cdn.auth0.com/js/lock/11.10.0/lock.min.js");

        Requirements::customScript(<<<JS
            function getUrlParameter(name) {
                name = name.replace(/[\[]/, '\\[').replace(/[\]]/, '\\]');
                var regex = new RegExp('[\\?&]' + name + '=([^&#]*)');
                var results = regex.exec(location.search);
                return results === null ? '' : decodeURIComponent(results[1].replace(/\+/g, ' '));
            }
            
            // window.dataLayer = window.dataLayer || [];

            // function gtm(w,d,s,l,i) {
            //     w[l]=w[l]||[];
            //     w[l].push({
            //         'gtm.start': new Date().getTime(), 
            //         event: 'gtm.js'
            //     });
            //     var f = d.getElementsByTagName(s)[0];
            //     var j = d.createElement(s);
            //     var dl = l!= 'dataLayer' ? '&l='+l : '';
            //     j.async=true;
            //     j.src='https://www.googletagmanager.com/gtm.js?id='+i+dl;
            //     f.parentNode.insertBefore(j,f);
            // }
            //
            // gtm(window,document,'script','dataLayer','GTM-W89MP26');
            //
            // function gtag() {
            //     dataLayer.push(arguments);
            // }

            var options = {
                allowAutocomplete: false,
                autofocus: true,
                autoclose: false,
                closable: true,
                language: 'nl',
                languageDictionary: {
                    emailInputPlaceholder: "email@adres.nl",
                    title: "",
                    signUpTerms: "Ik ga akkoord met het <a href='https://directlease.nl/privacy-statement/'>privacystatement</a> van DirectLease.",
                    signUpTitle: '',
                    signUpLabel: 'Registreren',
                    signUpSubmitLabel: 'Registreren',
                    forgotPasswordTitle: 'Wachtwoord vergeten?',
                    forgotPasswordInstructions: 'Geef je e-mailadres op, dan sturen wij een e-mail voor het resetten van je wachtwoord.',
                },
                theme: {
                   logo: 'https://directlease.nl/assets/Auth0/DirectLease-logo.png',
                   primaryColor: '#008cc8',
                   authButtons: {
                       "google-oauth2": {
                           displayName: "Google",
                           primaryColor: "#f3f3f3",
                           foregroundColor: "#000000",
                           icon: "https://cdn4.iconfinder.com/data/icons/new-google-logo-2015/400/new-google-favicon-512.png"
                      }
                      },
                },
                // TODO control this from the settings
                allowedConnections: ['facebook', 'google-oauth2', 'linkedin', 'Username-Password-Authentication'],
                auth: {
                    params: {
                        // TODO control this from the settings
                        scope: 'openid email profile user_metadata app_metadata'
                    }
                },
                // TODO control this from the settings
                configurationBaseUrl: 'https://cdn.eu.auth0.com',
                mustAcceptTerms: true,
                additionalSignUpFields: [{
                    name: "firstname",
                    placeholder: "Voornaam",
                    validator: function(firstname) {
                        return {
                            valid: firstname.length >= 1,
                            hint: 'Voornaam is verplicht'
                        };
                    }
                },
                {
                    name: "lastname",
                    placeholder: "Achternaam",
                    validator: function(lastname) {
                        return {
                            valid: lastname.length >= 1,
                            hint: 'Achternaam is verplicht'
                        };
                    }
                },
                {
                    type: "checkbox",
                    name: "accept_marketing",
                    prefill: "false",
                    placeholder: "Ja, houd me per mail als eerste op de hoogte van speciale aanbiedingen en acties" 
                }]
            };

            var email= getUrlParameter("email");
             
            if(email) {
                 options.prefill = {
                     email: email,
                 };
            }
        
            var lock = new Auth0Lock(
                '$auth0_client_id',
                '$auth0_domain',
                options
            );
            
            lock.on("signup submit", function() {
                localStorage.setItem('action', 'register');
            });
            
            lock.on("authorization_error", function(result) { 
                console.log("result:", result);
                if(result.error == "unauthorized") {
                    var options = {};
                    lock.hide();
                    options.flashMessage = {
                        type: 'error',
                        text: 'Uw emailadres is nog niet geverifieerd. Vraag s.v.p. een nieuw wachtwoord aan.'
                    };
                    setTimeout(function() {
                        lock.show(options);
                    }, 2000);
                }
            });
        
            // Listening for the authenticated event
            lock.on("authenticated", function (authResult) {
                let action = localStorage.getItem('action');
                // if(action == "register") {
                //     dataLayer.push({
                //         'event' : 'VirtualPageView-Register',
                //         'eventValue' : 'vpv-register'
                //     });
                // } else {
                //     dataLayer.push({
                //         'event' : 'VirtualPageView-Login',
                //         'eventValue' : 'vpv-login'
                //     });
                // }
                // Use the token in authResult to getUserInfo() and save it to localStorage
                lock.hide();
                // document.getElementById('loading-background').style.display = 'flex';
                lock.getUserInfo(authResult.accessToken, function (error, profile) {
                    if (error) {
                        window.location.href = localStorage.getItem("failedURL");
                        return;
                    }
                    localStorage.setItem('accessToken', authResult.accessToken);
                    // localStorage.setItem('profile', JSON.stringify(profile));
                    
                    var xhttp = new XMLHttpRequest();
                    xhttp.onreadystatechange = function() {
                        if (this.readyState == 4 && this.status == 200) {
                            if(localStorage.getItem("successURL")) {
                                let succesUrl =  localStorage.getItem("successURL");
                                localStorage.removeItem("successURL");
                                if(succesUrl.endsWith("application.&success=true")) {
                                    window.location.href = "/mijndirectlease/mijnprofiel";
                                } else {
                                    // window.location.href = succesUrl;
                                }
                            } else {
                                // window.location.href = "/mijndirectlease";
                            }
                        }
                    };
                    xhttp.open("POST", "api/loginFromAuth0", true);
                    xhttp.setRequestHeader("Content-type", "application/json");
                    xhttp.send(JSON.stringify(profile));
                    
                });
            });
            
            if ((location.pathname == "/Security/login/register") || (location.pathname == "/Security/login") ) {
                var options = {};
                if (location.pathname == "/Security/login/register") {
                     options = {
                         initialScreen: 'signUp'
                     };
                }
                
                lock.show(options);
                var backURL = location.search.split("BackURL=")[1];
        
                if(backURL) {
                    console.log('setting succesURL ' + backURL + ' in localStorage');
                    localStorage.setItem('successURL', window.location.origin + decodeURIComponent(backURL));
                }
            }
JS
        );
    }

    private function getConfigSetting($setting, $name)
    {
        $cs = $this->config()->get($setting);
        if($cs) {
            return $cs;
        } else {
            throw new \Error('The ' . $name . ' is missing in your configuration');
        }
    }

}

?>
