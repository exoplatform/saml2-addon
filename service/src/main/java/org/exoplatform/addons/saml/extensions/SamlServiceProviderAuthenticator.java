package org.exoplatform.addons.saml.extensions;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.gatein.sso.saml.plugin.valve.ServiceProviderAuthenticator;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.w3c.dom.Document;

import org.exoplatform.container.PortalContainer;
import org.exoplatform.services.cache.CacheService;

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
 * <p>
 * It also brings the user back to the page they asked for when the IDP and the
 * SP are not on the same site. The stock valve keeps that page in the session,
 * and a {@code SameSite=Lax} session cookie is not sent with the cross-site POST
 * of the IDP: the session is a new one and the user lands on the home page. This
 * valve sends an id of that page as the {@code RelayState}, that the IDP gives
 * back in the POST, and puts the page in the new session (see
 * {@link SamlRelayStates}). The signed query string of the HTTP-Redirect
 * binding already holds its {@code RelayState}: it is left as it is.
 */
public class SamlServiceProviderAuthenticator extends ServiceProviderAuthenticator {

  private static final String AUTHN_REQUEST = "AuthnRequest";

  final SamlRelayStates       relayStates   = new SamlRelayStates(this::cacheService);

  /**
   * The first thing the parent valve asks of a request, before it reads the
   * SAML answer ({@code if (saveRestoreRequest && matchRequest(request))}),
   * whatever the method Tomcat calls to authenticate: the page asked for is
   * restored here.
   */
  @Override
  protected boolean matchRequest(Request request) {
    restoreTargetOfTheLostSession(request);
    return super.matchRequest(request);
  }

  /**
   * The cache service of the portal of this web application. It is resolved from
   * the servlet context, not from the container of the thread: a worker thread
   * keeps the container of the last request it served, or none.
   *
   * @return the cache service, or null
   */
  CacheService cacheService() {
    Context context = getContext();
    PortalContainer container = PortalContainer.getInstance(context == null ? null : context.getServletContext());
    return container == null ? null : container.getComponentInstanceOfType(CacheService.class);
  }

  @Override
  protected void sendRequestToIDP(String destination,
                                  Document samlDocument,
                                  String relayState,
                                  Request request,
                                  Response response,
                                  boolean willSendRequest,
                                  String destinationQueryStringWithSignature) throws ProcessingException,
                                                                              ConfigurationException,
                                                                              IOException {
    // The signed query string of the HTTP-Redirect binding already holds its
    // RelayState: changing it would break the signature. The parent answers an
    // AJAX request with a 403: no page to come back to, and the background
    // requests of anonymous clients would fill the store.
    boolean ours = willSendRequest && destinationQueryStringWithSignature == null && isAuthnRequest(samlDocument)
        && !"XMLHttpRequest".equalsIgnoreCase(request.getHeader(GeneralConstants.HTTP_HEADER_X_REQUESTED_WITH));
    String id = ours ? rememberTarget(request) : null;
    super.sendRequestToIDP(destination,
                           samlDocument,
                           id == null ? relayState : id,
                           request,
                           response,
                           willSendRequest,
                           destinationQueryStringWithSignature);
  }

  /**
   * The parent valve has just saved the request of the user in the session, to
   * send them back to it. Keeps it under an id that does not depend on the
   * session.
   */
  String rememberTarget(Request request) {
    Session session = request.getSessionInternal(false);
    Object note = session == null ? null : session.getNote(Constants.FORM_REQUEST_NOTE);
    if (note instanceof SavedRequest saved && "GET".equals(saved.getMethod())) {
      SamlRelayTarget target = new SamlRelayTarget(saved.getRequestURI(),
                                                                 saved.getDecodedRequestURI(),
                                                                 saved.getQueryString());
      if (SamlRelayStates.isTargetOfThisApplication(request.getContextPath(), target)) {
        return relayStates.put(target);
      }
    }
    return null;
  }

  /**
   * The IDP answers with the id of the target in the RelayState. When the
   * session of that request is not the one that sent the user to the IDP, which
   * did not get its cookie, it holds no saved request: gives it the target.
   */
  void restoreTargetOfTheLostSession(Request request) {
    // A session that holds its saved request is left alone, before any parameter is read: the answer of the
    // IDP in a lost session has none
    Session known = request.getSessionInternal(false);
    if (known != null && known.getNote(Constants.FORM_REQUEST_NOTE) != null) {
      return;
    }
    // The parent has set the character encoding before it asks matchRequest
    String relayState = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY) == null ? null
                                                                                          : request.getParameter(GeneralConstants.RELAY_STATE);
    if (relayState == null) {
      return;
    }
    SamlRelayTarget target = relayStates.take(relayState);
    Session session = request.getSessionInternal(true);
    if (target == null || session.getNote(Constants.FORM_REQUEST_NOTE) != null
        || !SamlRelayStates.isTargetOfThisApplication(request.getContextPath(), target)) {
      return;
    }
    SavedRequest saved = new SavedRequest();
    saved.setMethod("GET");
    saved.setRequestURI(target.requestURI());
    saved.setDecodedRequestURI(target.decodedRequestURI());
    saved.setQueryString(target.queryString());
    session.setNote(Constants.FORM_REQUEST_NOTE, saved);
  }

  private static boolean isAuthnRequest(Document document) {
    if (document == null || document.getDocumentElement() == null) {
      return false;
    }
    // The local name is null for a document that is not namespace aware
    String name = document.getDocumentElement().getLocalName();
    if (name == null) {
      name = document.getDocumentElement().getNodeName();
      name = name.substring(name.indexOf(':') + 1);
    }
    return AUTHN_REQUEST.equals(name);
  }

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
