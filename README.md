SAML2 Addon
=======

Note:
SAML2 IDP integration only works for eXo Platform Jboss
SAML2 SP integration works for eXo Platform Jboss & Tomcat

### Install and configure Platform as Service provider (SP)
- Go to $PLATFORM_HOME than run this command to install exo-saml2 addon
```
./addon install exo-saml
```
- Edit `$PLATFORM_HOME/standalone/configuration/standalone-exo.xml` and uncomment configuration of `SSODelegateLoginModule` (under security domain `gatein-domain`).
Note: please replace `${gatein.sso.login.module.enabled}` to `#{gatein.sso.login.module.enabled}` and `${gatein.sso.login.module.class}` to `#{gatein.sso.login.module.class}`.
The `SSODelegateLoginModule` will look like:
```xml
<login-module code="org.gatein.sso.integration.SSODelegateLoginModule" flag="required">
    <module-option name="enabled" value="#{gatein.sso.login.module.enabled}"/>
    <module-option name="delegateClassName" value="#{gatein.sso.login.module.class}"/>
    <module-option name="portalContainerName" value="portal"/>
    <module-option name="realmName" value="gatein-domain"/>
    <module-option name="password-stacking" value="useFirstPass"/>
</login-module>
```
- Edit `$PLATFORM_HOME/standalone/configuration/gatein/exo.properties` then update these configurations (add them if they do not exist)
```
# SSO
gatein.sso.enabled=true
gatein.sso.saml.sp.enabled=true
gatein.sso.callback.enabled=${gatein.sso.enabled}
gatein.sso.login.module.enabled=${gatein.sso.enabled}
gatein.sso.filter.logout.enabled=false
gatein.sso.filter.login.sso.url=/@@portal.container.name@@/dologin
gatein.sso.filter.initiatelogin.enabled=false
gatein.sso.saml.config.file=${exo.conf.dir}/saml2/picketlink-sp.xml
gatein.sso.idp.host=www.idp.com
gatein.sso.idp.url=http://${gatein.sso.idp.host}:8087/portal/sso
gatein.sso.sp.url=http://www.sp.com:8080/portal/dologin
# WARNING: This bundled keystore is only for testing purposes. You should generate and use your own keystore!
gatein.sso.picketlink.keystore=${exo.conf.dir}/saml2/jbid_test_keystore.jks

# Uncomment this when JBoss is used

#gatein.sso.login.module.class=org.gatein.sso.agent.login.SAML2WildflyIntegrationLoginModule
#gatein.sso.uri.suffix=dologin

# Uncomment this when Tomcat is used

#gatein.sso.login.module.class=org.gatein.sso.agent.login.SAML2IntegrationLoginModule
#gatein.sso.valve.enabled=true
#gatein.sso.valve.class=org.gatein.sso.saml.plugin.valve.ServiceProviderAuthenticator
```
- Start Platform SP when using JBoss with
```
cd $GATEIN_SP_HOME/bin
./standalone.sh -b www.sp.com
```

### Install and configure Platform as Identity provider (IDP)
- Go to $PLATFORM_HOME than run this command to install exo-saml2 addon
```
./addon install exo-saml
```
- Edit `$PLATFORM_HOME/standalone/configuration/gatein/exo.properties` and update these configuration (add new if they do not exist)
```
# SSO
gatein.sso.enabled=true
gatein.sso.filter.login.enabled=false
gatein.sso.filter.logout.enabled=false
gatein.sso.filter.initiatelogin.enabled=false
gatein.sso.filter.saml.idp.enabled=true
gatein.sso.skip.jsp.redirection=false
gatein.sso.saml.signature.ignore=true
gatein.sso.saml.config.file=${exo.conf.dir}/saml2/picketlink-idp.xml
gatein.sso.idp.url=http://www.idp.com:8087/portal/sso
gatein.sso.sp.domains=sp.com
gatein.sso.sp.host=www.sp.com
# WARNING: This bundled keystore is only for testing purposes. You should generate and use your own keystore in production!
gatein.sso.picketlink.keystore=${exo.conf.dir}/saml2/jbid_test_keystore.jks
```
- Start Platform IDP with:
```
cd GATEIN_IDP_HOME/bin
./standalone.sh -b www.idp.com
```

### Setup with external IDP using REST callback
##### Configure Platform SP
You will need configure Platform follow the SP section, but you will need change one configuration
```
gatein.sso.idp.url=http://${gatein.sso.idp.host}:8080/idp-sig/
```
##### Configure external IDP
We will use another platform package to deploy `idp-sig.war`. Do not confuse this package with eXo Platform IDP described in previous section.
This package is used to run `idp-sig.war`.
- copy `$PLATFORM_SP_HOME/saml-plugin/idp-sig.war` to `$PLATFORM_IDP_HOME/standalone/deployments`
- Create an empty file named `idp-sig.war.dodeploy` under `$PLATFORM_IDP_HOME/standalone/deployments`
- Remove `$PLATFORM_IDP_HOME/standalone/deployments/platform.ear.dodeploy`, so that `platform.ear` will not be deployed
- Copy folder `$PLATFORM_SP_HOME/saml-plugin/idp-sig-module/module` into `$PLATFORM_IDP_HOME`
- Add the following security domain to the `$PLATFORM_IDP_HOME/standalone/configuration/standalone.xml` file:
```xml
<security-domain name="idp" cache-type="default">
   <authentication>
      <login-module code="org.gatein.sso.saml.plugin.SAML2IdpLoginModule" flag="required">
         <module-option name="gateInURL" value="http://www.sp.com:8080/portal"/>
      </login-module>
   </authentication>
</security-domain>
```
- Start the IDP with options as follows:
```
./standalone.sh -b www.idp.com -c standalone.xml -Dsp.host=www.sp.com -Dsp.domains=sp.com -Dpicketlink.keystore=/jbid_test_keystore.jks
```

### SAML2 scenario with eXo Platform and Salesforce

##### Configure Salesforce as SP and Platform as IDP
###### Configure Salesforce as SP
- Sign up at http://developer.force.com
-  Set up your domain by selecting `Setup` → `Domain Management` → `My Domain`
![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_my_domain.png)
- Set up SSO by go to `Setup` → `Security Controls` → `Single Sign-On Settings`, then check `SAML Enabled`
- Then create a new `SAML Single Sign-On Setting`
![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_SP_SSO_settings.png)
    - Issuer: The eXo Platform IDP URL, like `http://www.idp.com/portal/dologin`
    - SAML Identity Type: Select Assertion contains the Federation ID from the User object
    - SAML Identity Location: Select Identity is in the NameIdentifier element of the Subject statement.
    - Identity Provider Login(/Logout) URL: `http://www.idp.com/portal/dologin`
    - Entity ID: Now, it should be `https://saml.salesforce.com`
    - Certificate: Export a `.crt` file from your keystore to be uploaded here. The command to export:
    ```
    keytool -export -keystore secure-keystore.jks -alias secure-key -file test-certificate.crt
    ```
    In case you use `jbid_test_keystore.jks` as keystore, the command will be:
    ```
    keytool -export -keystore jbid_test_keystore.jks -alias servercert -file test-certificate.crt
    ```
    The keystore password is store123
    
- Back to the `My Domain` screen and edit the `Login Page Branding` section. Check your SSO Setting item(s) in the `Authentication Service`
![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_SP_login_page_branding.png)

###### Configure Platform as IDP
- Follow the guideline at `Install and configure Platform as Identity provider (IDP)` section above.
- Upddate below configuration
```
gatein.sso.sp.domains=saml.salesforce.com
gatein.sso.sp.host=saml.salesforce.com
```
- Edit `$PLATFORM_IDP_HOME/standalone/deployments/platform.ear/exo.portal.web.portal.war!/WEB-INF/conf/sso/saml/picketlink-idp.xml`
    - Add domain `saml.salesforce.com` as a ValidatingAlias
    ```
    <KeyProvider ...>
        <ValidatingAlias Key="${gatein.sso.sp.host}" Value="secure-key"/>
        <ValidatingAlias Key="saml.salesforce.com" Value="salesforce-cert"/>
    </KeyProvider>
    ```
    `salesforce-cert` is the alias that you will import to your keyfile in later step
- Download SP Metadata file from your Salesforce SSO Setting page, by clicking `Download Metadata`, then save this file with name `sp-metadata.xml`
![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_SP_download_metadata.png)
- Edit the downloaded `sp-metadata.xml` file then add `EntitiesDescriptor` as root tag of this xml file. This file will look like
```xml
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://saml.salesforce.com" validUntil="2025-01-09T02:22:00.551Z">
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://saml.salesforce.com" validUntil="2025-01-09T02:22:00.551Z">
    ....
    </md:EntityDescriptor>
</md:EntitiesDescriptor>
```
- Continue edit `sp-metadata.xml`, than update `AuthnRequestsSigned="true"` to `AuthnRequestsSigned="false"`
- Copy this `sp-metadata.xml` file into `$PLATFORM_IDP_HOME/standalone/deployments/platform.ear/exo.portal.web.portal.war!/WEB-INF/conf/sso/saml/`
- Continue modify `$PLATFORM_IDP_HOME/standalone/deployments/platform.ear/exo.portal.web.portal.war!/WEB-INF/conf/sso/saml/picketlink-idp.xml` to add MetaDataProvider element as follows
```xml
<PicketLinkIDP ...>
    ...
    <MetaDataProvider ClassName="org.picketlink.identity.federation.core.saml.md.providers.FileBasedEntitiesMetadataProvider">
        <Option Key="FileName" Value="/WEB-INF/conf/sso/saml/sp-metadata.xml"/>
    </MetaDataProvider>
</PicketLinkIDP>
```
- Download and import Salesforce client certificate:
     - The link to download new certificate should be found at http://wiki.developerforce.com/page/Client_Certificate. 
        At the moment, you can use this link: http://s3.amazonaws.com/dfc-wiki/en/images/3/34/New_proxy.salesforce.com_certificate_chain.zip. 
        Download and unzip it, you will see a file named proxy-salesforce-com.123. 
     - Import the certificate into your keystore file with the command below
     ```
     keytool -import -keystore secure-keystore.jks -file proxy-salesforce-com.123 -alias salesforce-cert
     ```
     In case you use `jbid_test_keystore.jks` as keystore, the command will be:
     ```
     keytool -import -keystore jbid_test_keystore.jks -file proxy-salesforce-com.123 -alias salesforce-cert
     ```

##### Configure Salesforce as IDP and Platform as SP
#####  Configuring Salesforce as SAML2 IDP 
- If you configured Salesforce as SAML2 SP as above section, you will have to disable it.
- Enable Identity Provider by go to `Setup` → `Security Controls` → `Identity Provider`, then click `Enable Identity Provider`. Accept the default certificate by clicking Save. You can change it later if you need.
![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_IDP_enable.png)
- Create `Connected Apps`
    - Click the link in the `Service Providers` section
    ![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_IDP_Connected_Apps_1.png)
    - Fill in all required information. In the `Web App Settings` section, check `Enable SAML` and complete the following information
    ![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_IDP_Connected_Apps_2.png)
        - Entity ID: The SP login URL, like `http://www.sp.com:8080/portal/dologin`
        - ACS URL: The URL of the Assertion Consumer Service. In this scenario, it is `http://www.sp.com:8080/portal/dologin` too
        - Subject Type: Select `Federation ID`
        - Name ID Format: Select `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
        - Issuer: Use your domain like `https://exodoc-dev-ed.my.salesforce.com`
- Make sure your connected application can be accessed by users who have the "Standard Platform User" profile
    - Click `Manage Apps` → `Connected Apps`
    ![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_IDP_Manage_Apps.png)
    - Find your app and click to view it. In the `Profiles` section, you can manage Profiles that have access to your app. At this time, make sure you see the "Standard Platform User" because this is needed for testing later

##### Configuring Platform as SAML2 SP
- Configure Platform follow the `Install and configure Platform as Service provider (SP)` section above
- Update these configuration:
```
gatein.sso.idp.host=exodoc-dev-ed.my.salesforce.com
gatein.sso.idp.url=https://exodoc-dev-ed.my.salesforce.com/idp/endpoint/HttpPost
gatein.sso.sp.url=http://www.sp.com:8080/portal/dologin
```
- Download and import Salesforce IDP certificate to your keystore. The Salesforce IDP certificate is downloaded from the `Identity Provider` page
![alt tag](http://docs.exoplatform.com/public/topic/PLF41/images/AuthenticationAndIdentity/SSO/Salesforce_IDP_download_certificate.png)
Then import this certificate to your keystore with command like this:
```
keytool -import -keystore secure-keystore.jks -file SelfSignedCert_17Oct2013_070921.crt -alias salesforce-idp
```
`SelfSignedCert_17Oct2013_070921.crt` is downloaded file.
In case you are using `jbid_test_keystore.jks` the command will be (the store password is `store123`):
```
keytool -import -keystore jbid_test_keystore.jks -file SelfSignedCert_17Oct2013_070921.crt -alias salesforce-idp
```
- Modify `$PLATFORM_SP_HOME/standalone/deployments/platform.ear/exo.portal.web.portal.war/WEB-INF/conf/sso/saml/picketlink-sp.xml` and update value of `ValidatingAlias` key `${gatein.sso.idp.host}` to `salesforce-idp`
```
<ValidatingAlias Key="${gatein.sso.idp.host}" Value="salesforce-idp"/>
```
- Start Platform as SP then test it

### SAML2 scenario with eXo Platform and Google App
- Install and configure Platform following `Install and configure Platform as Identity provider (IDP)` section.
- Follow the document at: http://docs.exoplatform.com/public/topic/PLF41/sect-Reference_Guide-Single_Sign_On-SAML2.PLF-GoogleApps.html?cp=2_8_4_7_4_4
