package org.exoplatform.addons.saml.extensions;

import java.io.IOException;

import org.gatein.sso.saml.plugin.filter.SAML2LogoutFilter;
import org.picketlink.common.constants.GeneralConstants;

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
      delegateToSamlLogout(servletRequest, servletResponse, filterChain);
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
   * @return true when the session was opened by the SAML workflow, or when its
   *         SAML logout is already in progress
   */
  public static boolean isSamlSession(HttpServletRequest request) {
    HttpSession session = request.getSession(false);
    return session != null
        && (session.getAttribute(GeneralConstants.PRINCIPAL_ID) != null
            || session.getAttribute(SAML_LOGOUT_ATTRIBUTE) != null);
  }

}
