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
gatein.sso.valve.enabled=true
gatein.sso.valve.class=org.gatein.sso.saml.plugin.valve.ServiceProviderAuthenticator
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
gatein.sso.idp.url.logout=IDP_SAML_ENDPOINT_LOGOUT
gatein.sso.idp.alias=IDP_SIGNING_ALIAS
gatein.sso.sp.alias=SP_SIGNING_ALIAS
gatein.sso.sp.signingkeypass=SP_SIGNING_KEY_PASS
gatein.sso.picketlink.keystorepass=SP_KEYSTORE_PASS
# WARNING: This bundled keystore is only for testing purposes. You should generate and use your own keystore!
gatein.sso.picketlink.keystore=${exo.conf.dir}/saml2/jbid_test_keystore.jks
```
Note: The following properties values must be configured
```
IDP_SAML_ENDPOINT: Saml IDP Endpoint: Example, http://idp.com/saml
IDP_SAML_ENDPOINT_LOGOUT: Saml IDP Logout Endpoint: Example, http://idp.com/saml/logout
IDP_SIGNING_ALIAS: Certificate Alias in selected Keystore file, Example: idpalias
IDP_SIGNING_KEY_PASS: Certificates Keystore Password, Example: test123
IDP_KEYSTORE_PASS: SSL Keystore Password, Example: store123
```
- Start eXo Platform with
```
cd $PLATFORM_HOME
./start_eXo.sh
```
### Keep the portal login page next to the SAML login (optional)
By default, eXo does not display a login page of its own: a visitor who needs to sign in is redirected to the IDP.
This optional mode keeps the portal login page (like with OpenID) and adds a **Sign in with SAML** button that starts the SAML workflow.
Without the flag below, nothing changes.

Add to `$PLATFORM_HOME/gatein/conf/exo.properties`:
```
gatein.sso.skip.jsp.redirection=false
gatein.sso.saml.login.page.enabled=true
gatein.sso.filter.logout.class=org.exoplatform.addons.saml.extensions.HybridSAML2LogoutFilter
# Together with the logout filter above: the SAML logout of a user whose portal session was recreated (see the notes)
gatein.sso.valve.class=org.exoplatform.addons.saml.extensions.SamlServiceProviderAuthenticator
# Optional: clients that must use the SAML login
gatein.sso.saml.login.enforced.ips=10.0.0.0/8, 192.168.1.10, 172.16.5.1-172.16.5.50
```

| Property | Description | Default |
|----|----|----|
| `gatein.sso.skip.jsp.redirection` | Must be exactly `false`, so that the portal login page is displayed (portal property) | follows `gatein.sso.enabled` |
| `gatein.sso.saml.login.page.enabled` | Displays the SAML button on the login page, and enables the enforced IP list below. Needs `gatein.sso.enabled=true` | `false` |
| `gatein.sso.filter.logout.class` | `org.exoplatform.addons.saml.extensions.HybridSAML2LogoutFilter` starts the SAML logout (the redirection to the IDP) only for users who signed in with SAML. Users who signed in with a local password get the regular portal logout. With the stock `SAML2LogoutFilter`, their logout ends on a blank page and the session stays half closed. `gatein.sso.filter.logout.enabled` must stay `true` | `org.gatein.sso.saml.plugin.filter.SAML2LogoutFilter` |
| `gatein.sso.valve.class` | `org.exoplatform.addons.saml.extensions.SamlServiceProviderAuthenticator`, to set together with `HybridSAML2LogoutFilter` (it fixes nothing without it): the SAML user gets a principal that Tomcat's single sign-on valve keeps, so that the logout of a user whose portal session was recreated still goes through the IDP (see the notes). It does not apply with `requireReauthentication="true"` on Tomcat's `SingleSignOn` valve, nor to the JBoss branch of the parent valve. It keeps `gatein.sso.saml.username.forcelowercase` and the e-mail to username mapping | `org.gatein.sso.saml.plugin.valve.ServiceProviderAuthenticator` |
| `gatein.sso.saml.login.enforced.ips` | Optional. IP addresses, CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`) and ranges (`10.1.1.10-10.1.1.20`), separated by comma, semicolon or space (spaces around `-` and `/` are accepted). Host names are not accepted. An invalid entry enforces nothing and is logged at error level: check the startup log line `SAML login enforced for the client addresses`. For an unauthenticated client whose address is listed (or cannot be parsed), `/portal/login`, `/portal/doLogin` and `/portal/dologin/` redirect to `<context>/sso` (the SAML workflow) instead of showing the login page or accepting a password, and the portal's remember-me filter ignores the remember-me cookie of a local login (except at exactly `/portal/logout`, which still deletes its token: a variant such as `/portal/logout;x=1` is handled like any other path) | empty |

Notes:
- **Label.** The button label comes from the `UILoginForm.label.provider.saml` key of the Login portlet bundle ("Sign in with SAML", added to the `social` bundle by EXO-94422), or from the provider label set in the settings of the Login portlet. A platform version without that key shows "Sign in with Saml".
- **Client address.** The list is matched against the remote address of the request. The `X-Forwarded-For` header is never read by the add-on, but the platform's Tomcat `RemoteIpValve` replaces the remote address with its value when the direct peer is one of its trusted proxies (`internalProxies`, by default every private range). With the default settings, a client of a private network can therefore choose the address it is seen with: restrict `internalProxies` to your real reverse proxies, otherwise the list can be bypassed. A list with only IPv4 entries does not match a client that reaches the server over IPv6, and conversely.
- **What is enforced.** The login page and its form, and the remember-me cookie, in the portal web application (`/portal`). It is **not** an access control. It does not cover the HTTP Basic and Digest authentication of the REST (`/rest/private`) and WebDAV web applications, which also give a portal session through Tomcat's single sign-on valve; the REST endpoints of the Spring-based web applications (`/social/rest`, those of the add-ons), which still accept the remember-me cookie; a remember-me cookie sent together with any password in an HTTP Basic request to the REST or WebDAV web applications, because the login module of the platform reads the raw request and signs in as the owner of the token; nor OpenID or the other providers of the login page. Block these at the reverse proxy for the networks that must use SAML.
- Without the flag, a local password can still be submitted to `/portal/login`, as before.
- **Logout of a SAML user whose portal session expired.** `HybridSAML2LogoutFilter` recognises a SAML user by a marker of the portal session, written when the IDP answers. If that session expires while the user keeps a session in another web application (`/rest`, WebDAV), Tomcat's single sign-on valve signs the user back in to a new portal session without the marker: the logout is then the regular portal logout, the session at the IDP stays open, and the next **Sign in with SAML** needs no password. This is not specific to this mode: any SAML deployment whose users keep such a session meets it, and the stock `SAML2LogoutFilter` does not avoid it (it asks the IDP to end the session of the user it reads from the marker of the portal session, finds none and answers an empty response). To close it, set `gatein.sso.valve.class=org.exoplatform.addons.saml.extensions.SamlServiceProviderAuthenticator` beside `gatein.sso.filter.logout.class=org.exoplatform.addons.saml.extensions.HybridSAML2LogoutFilter`: the valve gives the SAML user a principal that the single sign-on valve keeps (it also keeps the subject the IDP sent, which the logout request names), and the logout filter recognises it and writes the marker back. Neither works alone. It needs Tomcat's `SingleSignOn` valve at its default (`requireReauthentication` not set to `true`: Tomcat would then authenticate the user again instead of replaying the principal, and the marker would not be kept) and does not apply to the JBoss branch of the parent valve. Without the pair, on shared computers, close the browser after logging out.
- If the IDP refuses a user of an enforced address, that client has no local fallback login.

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

#### Configure NameId format
When using saml2-addon, exo needs the user identifier in the name-id field of the assertion.

To configure it, there is 2 options : 
- On IDP side : some IDPs allows to force the name-id format neverming the name-id requested in the SAMLRequest assertion. In this case, you can configure 
  - persistent : the nameid will be a unique identifier, which will not change during this. This id must be the username in eXo
  - unspecified : then you can choose a user attribute like username as name id
- On exo side : the property `gatein.sso.saml.nameid.format` allow to configure the wanted nameid format. By dafault, value is `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`. It can be changed to `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` if needed

#### Set username in other field than nameid
In some installation, IDP requires that nameid is not the username but a numeric id. In this case, you can set the username in another field by setting theses properties in exo.properties
```
gatein.sso.saml.use.namedid=false
gatein.sso.saml.subject.attribute=uid
```

With this configuration, the username or email will be read in the attribute provided by the assertion.


