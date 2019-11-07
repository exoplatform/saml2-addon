SAML2 Addon
=======

### Install and configure eXo Platform as Service provider (SP)
- Go to $PLATFORM_HOME than run this command to install exo-saml2 addon
```
./addon install exo-saml
```
- Add the following properties to $PLATFORM_HOME/gatein/conf/exo.properties
```
gatein.sso.enabled=true
gatein.sso.saml.sp.enabled=true
gatein.sso.callback.enabled=true
gatein.sso.login.module.enabled=true
gatein.sso.login.module.class=org.gatein.sso.agent.login.SAML2IntegrationLoginModule
gatein.sso.valve.enabled=true
gatein.sso.valve.class=org.picketlink.identity.federation.bindings.tomcat.sp.ServiceProviderAuthenticator
gatein.sso.filter.login.sso.url=/portal/dologin
gatein.sso.filter.initiatelogin.enabled=false
gatein.sso.filter.logout.enabled=true
gatein.sso.filter.logout.class=org.gatein.sso.saml.plugin.filter.SAML2LogoutFilter
gatein.sso.filter.logout.url=${gatein.sso.sp.url}?GLO=true 

# Custom properties

gatein.sso.sp.host=SP_HOSTNAME
gatein.sso.sp.url=${gatein.sso.sp.host}/portal/dologin
gatein.sso.idp.host=IDP_HOSTNAME
gatein.sso.idp.url=IDP_SAML_ENDPOINT
gatein.sso.idp.alias=IDP_SIGNING_ALIAS
gatein.sso.idp.signingkeypass=IDP_SIGNING_KEY_PASS
gatein.sso.idp.keystorepass=IDP_KEYSTORE_PASS
# WARNING: This bundled keystore is only for testing purposes. You should generate and use your own keystore!
gatein.sso.picketlink.keystore=${exo.conf.dir}/saml2/jbid_test_keystore.jks
```
Note: The following properties values must be configured
```
IDP_SAML_ENDPOINT: Saml IDP Endpoint: Example, http://idp.com/saml
IDP_SIGNING_ALIAS: Certificate Alias in selected Keystore file, Example: idpalias
IDP_SIGNING_KEY_PASS: Certificates Keystore Password, Example: test123
IDP_KEYSTORE_PASS: SSL Keystore Password, Example: store123
```
- Start eXo Platform with
```
cd $PLATFORM_HOME
./start_eXo.sh
```
### SAML2 scenario with eXo Platform and Salesforce
##### Configure Salesforce as IDP and Platform as SP
#####  Configuring Salesforce as SAML2 IDP 
- If you configured Salesforce as SAML2 SP as above section, you will have to disable it.
- Enable Identity Provider by go to `Setup` → `Security Controls` → `Identity Provider`, then click `Enable Identity Provider`. Accept the default certificate by clicking Save. You can change it later if you need.
![alt tag](https://docs.exoplatform.org/en/latest/_images/Salesforce_IDP_enable.png)
- Create `Connected Apps`
    - Click the link in the `Service Providers` section
    ![alt tag](https://docs.exoplatform.org/en/latest/_images/Salesforce_IDP_Connected_Apps_1.png)
    - Fill in all required information. In the `Web App Settings` section, check `Enable SAML` and complete the following information
    ![alt tag](https://docs.exoplatform.org/en/latest/_images/Salesforce_IDP_Connected_Apps_2.png)
        - Entity ID: The SP login URL, like `http://www.sp.com:8080/portal/dologin`
        - ACS URL: The URL of the Assertion Consumer Service. In this scenario, it is `http://www.sp.com:8080/portal/dologin` too
        - Subject Type: Select `Federation ID`
        - Name ID Format: Select `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
        - Issuer: Use your domain like `https://exodoc-dev-ed.my.salesforce.com`
- Make sure your connected application can be accessed by users who have the "Standard Platform User" profile
    - Click `Manage Apps` → `Connected Apps`
    ![alt tag](https://docs.exoplatform.org/en/latest/_images/Salesforce_IDP_Manage_Apps.png)
    - Find your app and click to view it. In the `Profiles` section, you can manage Profiles that have access to your app. At this time, make sure you see the "Standard Platform User" because this is needed for testing later

##### Configuring eXo Platform
- Configure Platform follow the `Install and configure eXo Platform as Service provider (SP)` section above
- Update these configuration:
```
gatein.sso.idp.host=exodoc-dev-ed.my.salesforce.com
gatein.sso.idp.url=https://exodoc-dev-ed.my.salesforce.com/idp/endpoint/HttpPost
gatein.sso.sp.url=http://www.sp.com:8080/portal/dologin
```
- Download and import Salesforce IDP certificate to your keystore. The Salesforce IDP certificate is downloaded from the `Identity Provider` page
![alt tag](https://docs.exoplatform.org/en/latest/_images/Salesforce_IDP_download_certificate.png)
Then import this certificate to your keystore with command like this:
```
keytool -import -keystore secure-keystore.jks -file SelfSignedCert_17Oct2013_070921.crt -alias salesforce-idp
```
`SelfSignedCert_17Oct2013_070921.crt` is downloaded file.
In case you are using `jbid_test_keystore.jks` the command will be (the store password is `store123`):
```
keytool -import -keystore jbid_test_keystore.jks -file SelfSignedCert_17Oct2013_070921.crt -alias salesforce-idp
```
- Modify `$PLATFORM_SP_HOME/gatein/conf/exo.properties` and update value of `gatein.sso.idp.alias` property
```
gatein.sso.idp.alias=idpalias
```
- Start eXo Platform as SP then test it
