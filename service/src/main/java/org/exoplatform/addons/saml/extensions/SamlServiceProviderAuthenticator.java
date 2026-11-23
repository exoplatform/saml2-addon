package org.exoplatform.addons.saml.extensions;

import java.security.Principal;
import java.util.List;

import org.apache.catalina.connector.Request;
import org.gatein.sso.saml.plugin.valve.ServiceProviderAuthenticator;
import org.picketlink.common.constants.GeneralConstants;

import jakarta.servlet.http.HttpSession;

/**
 * The {@link ServiceProviderAuthenticator} of the SAML workflow, with a
 * {@link SamlPrincipal} for the user it authenticates.
 * <p>
 * Optional: with it, {@link HybridSAML2LogoutFilter} still starts the SAML
 * logout of a user whose portal session expired while they kept a session in
 * another web application and was recreated by Tomcat's single sign-on valve.
 * The single sign-on valve of Tomcat must replay the principal it is given:
 * with {@code requireReauthentication="true"} on that valve, Tomcat
 * authenticates the user again instead, and the marker is not kept. The JBoss
 * branch of the parent valve does not call this method either.
 * Configure it with
 * {@code gatein.sso.valve.class=org.exoplatform.addons.saml.extensions.SamlServiceProviderAuthenticator}
 */
public class SamlServiceProviderAuthenticator extends ServiceProviderAuthenticator {

  @Override
  protected Principal getGenericPrincipal(Request request, String username, List<String> roles) {
    // The parent applies gatein.sso.saml.username.forcelowercase to the name
    String name = super.getGenericPrincipal(request, username, roles).getName();
    return new SamlPrincipal(name, roles, subjectOf(request));
  }

  /**
   * The SAML workflow has written the subject sent by the IDP in the session
   * that is being authenticated, before this valve maps it to a username.
   */
  private static String subjectOf(Request request) {
    HttpSession session = request.getSession(false);
    Object marker = session == null ? null : session.getAttribute(GeneralConstants.PRINCIPAL_ID);
    return marker instanceof Principal principal ? principal.getName() : null;
  }

}
