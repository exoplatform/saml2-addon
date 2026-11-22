package org.exoplatform.addons.saml.extensions;

import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;

/**
 * The principal of a user authenticated through the SAML workflow.
 * <p>
 * Tomcat's single sign-on valve keeps the principal of a login and gives it
 * back to the next portal session of the same browser. The marker in the
 * portal session is lost with that session, so the type of the principal is
 * what still tells a SAML login when the valve signs the user back in. See
 * {@link SamlServiceProviderAuthenticator} and
 * {@link HybridSAML2LogoutFilter#isSamlSession}.
 * <p>
 * The name is the eXo username, after the mapping of the valve (e-mail to
 * username, lower case). The subject is what the IDP sent: the SAML logout
 * asks the IDP to end the session of that subject, not of the eXo username.
 */
public class SamlPrincipal extends GenericPrincipal {

  private static final long serialVersionUID = 1L;

  private final String      subject;

  public SamlPrincipal(String name, List<String> roles) {
    this(name, roles, null);
  }

  /**
   * @param name the eXo username
   * @param roles the roles of the user
   * @param subject the subject sent by the IDP, or null when it is the name
   */
  public SamlPrincipal(String name, List<String> roles, String subject) {
    super(name, roles);
    this.subject = subject;
  }

  /**
   * @return the subject sent by the IDP (the NameID, or the value of the
   *         subject attribute), or the name when it is not known
   */
  public String getSubject() {
    return subject == null ? getName() : subject;
  }

}
