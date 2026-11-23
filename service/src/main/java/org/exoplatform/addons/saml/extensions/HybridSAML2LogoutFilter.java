package org.exoplatform.addons.saml.extensions;

import java.io.IOException;

import org.gatein.sso.saml.plugin.filter.SAML2LogoutFilter;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.core.SerializablePrincipal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

/**
 * A {@link SAML2LogoutFilter} that only starts the SAML logout (redirection
 * to the IDP) for users that were authenticated through SAML.
 * <p>
 * When the portal login page is kept next to the SAML login (see
 * {@link SamlLoginParamsExtension}), some users sign in with a local
 * password: they have no session at the IDP, so the SAML logout workflow
 * would end on a blank page and leave the session half logged out. Those
 * users get the regular portal logout instead.
 * <p>
 * A session counts as a SAML one through the marker the SAML workflow writes
 * in the portal session, or through the {@link SamlPrincipal} of the user
 * when the valve of the add-on ({@link SamlServiceProviderAuthenticator}) is
 * configured. Known limit without that valve: when the portal session expires
 * while the user keeps a session in another web application (REST, WebDAV),
 * Tomcat's single sign-on valve signs the user back in to a new portal
 * session that has no marker: that user then gets the regular portal logout,
 * and the session at the IDP stays open, so the next SAML login needs no
 * password.
 * <p>
 * Configure it with
 * {@code gatein.sso.filter.logout.class=org.exoplatform.addons.saml.extensions.HybridSAML2LogoutFilter}
 */
public class HybridSAML2LogoutFilter extends SAML2LogoutFilter {

  @Override
  public void doFilter(ServletRequest servletRequest,
                       ServletResponse servletResponse,
                       FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    if (isPortalLogoutInProgress(request) && !isSamlSession(request)) {
      filterChain.doFilter(servletRequest, servletResponse);
    } else {
      restoreSamlMarker(request);
      delegateToSamlLogout(servletRequest, servletResponse, filterChain);
    }
  }

  /**
   * The request of the SAML logout is built from the principal of the
   * request, but the filter of the SAML workflow then reads the user from the
   * marker of the portal session only, and ends the response without a
   * redirection when it has none. A session recreated by Tomcat's single
   * sign-on valve has no marker, only the {@link SamlPrincipal} of the user:
   * the marker the SAML login writes (a {@link SerializablePrincipal} of the
   * subject the IDP sent, which the logout request names) is written back
   * before the workflow starts.
   *
   * @param request current request
   */
  private void restoreSamlMarker(HttpServletRequest request) {
    if (isPortalLogoutInProgress(request) && request.getUserPrincipal() instanceof SamlPrincipal samlPrincipal) {
      HttpSession session = request.getSession();
      if (session.getAttribute(GeneralConstants.PRINCIPAL_ID) == null) {
        session.setAttribute(GeneralConstants.PRINCIPAL_ID, new SerializablePrincipal(samlPrincipal.getSubject()));
      }
    }
  }

  /**
   * The SAML logout workflow of the parent filter (redirection to the IDP).
   * Also called for the requests that are not a logout, which it passes on.
   *
   * @param servletRequest current request
   * @param servletResponse current response
   * @param filterChain the filter chain
   * @throws IOException on an I/O error
   * @throws ServletException on a servlet error
   */
  protected void delegateToSamlLogout(ServletRequest servletRequest,
                                      ServletResponse servletResponse,
                                      FilterChain filterChain) throws IOException, ServletException {
    super.doFilter(servletRequest, servletResponse, filterChain);
  }

  /**
   * @param request current request
   * @return true when the user signed in through the SAML workflow (the
   *         principal is a {@link SamlPrincipal}, or the session was opened by
   *         the workflow), or when its SAML logout is already in progress
   */
  public static boolean isSamlSession(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    return request.getUserPrincipal() instanceof SamlPrincipal
        || session != null
            && (session.getAttribute(GeneralConstants.PRINCIPAL_ID) != null
                || session.getAttribute(SAML_LOGOUT_ATTRIBUTE) != null);
  }

}
