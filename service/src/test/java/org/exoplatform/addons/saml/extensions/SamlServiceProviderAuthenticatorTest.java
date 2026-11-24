package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Principal;
import java.util.List;
import java.util.Set;

import org.apache.catalina.Context;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.w3c.dom.Document;
import org.mockito.ArgumentCaptor;

import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.services.cache.CacheService;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.core.SerializablePrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpSession;

public class SamlServiceProviderAuthenticatorTest {

  private static final String FORCE_LOWER_CASE = "gatein.sso.saml.username.forcelowercase";

  private final CacheService cacheService = SamlRelayStatesTest.realCacheService();

  private final TestValve valve = new TestValve(cacheService);


  @AfterEach
  public void clearProperty() {
    System.clearProperty(FORCE_LOWER_CASE);
  }

  @Test
  public void theUserOfTheSamlWorkflowGetsASamlPrincipal() {
    Principal principal = valve.getGenericPrincipal(mock(Request.class), "root", List.of("users", "administrators"));

    SamlPrincipal samlPrincipal = assertInstanceOf(SamlPrincipal.class, principal);
    assertEquals("root", samlPrincipal.getName());
    assertEquals(Set.of("users", "administrators"), Set.of(samlPrincipal.getRoles()));
  }

  @Test
  public void theNameKeepsItsCaseByDefault() {
    assertEquals("Root", valve.getGenericPrincipal(mock(Request.class), "Root", List.of()).getName());
  }

  @Test
  public void theNameIsLowerCasedWhenTheParentValveIsConfiguredToDoSo() {
    System.setProperty(FORCE_LOWER_CASE, "true");

    Principal principal = valve.getGenericPrincipal(mock(Request.class), "Root", List.of("users"));

    assertInstanceOf(SamlPrincipal.class, principal);
    assertEquals("root", principal.getName());
  }

  private static Request requestOfASessionWithTheSubject(String subject) {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(GeneralConstants.PRINCIPAL_ID)).thenReturn(new SerializablePrincipal(subject));
    Request request = mock(Request.class);
    when(request.getSession(false)).thenReturn(session);
    return request;
  }

  @Test
  public void thePrincipalKeepsTheSubjectTheIdpSentWhenTheNameIsMapped() {
    // the IDP identifies the user by e-mail, the parent valve maps it to the eXo username
    SamlPrincipal principal = assertInstanceOf(SamlPrincipal.class,
                                               valve.getGenericPrincipal(requestOfASessionWithTheSubject("John.Doe@corp.com"),
                                                                         "jdoe",
                                                                         List.of("users")));

    assertEquals("jdoe", principal.getName());
    assertEquals("John.Doe@corp.com", principal.getSubject());
  }

  @Test
  public void theSubjectKeepsItsCaseWhenTheNameIsLowerCased() {
    System.setProperty(FORCE_LOWER_CASE, "true");

    SamlPrincipal principal = assertInstanceOf(SamlPrincipal.class,
                                               valve.getGenericPrincipal(requestOfASessionWithTheSubject("John.Doe"),
                                                                         "John.Doe",
                                                                         List.of()));

    assertEquals("john.doe", principal.getName());
    assertEquals("John.Doe", principal.getSubject());
  }

  @Test
  public void withoutASubjectInTheSessionTheSubjectIsTheName() {
    assertEquals("root", ((SamlPrincipal) valve.getGenericPrincipal(mock(Request.class), "root", List.of())).getSubject());
  }

  @Test
  public void theTypeOfThePrincipalSurvivesTheSerializationOfASession() throws Exception {
    // The single sign-on valve of a cluster, or the persistence of the sessions, serializes the principal it keeps
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(valve.getGenericPrincipal(requestOfASessionWithTheSubject("root@corp.com"), "root", List.of("users")));
    }
    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      Object copy = in.readObject();

      assertInstanceOf(SamlPrincipal.class, copy);
      assertEquals("root", ((SamlPrincipal) copy).getName());
      assertEquals("root@corp.com", ((SamlPrincipal) copy).getSubject());
    }
  }


  // The IDP answers with a cross-site POST that does not carry the session cookie

  private static Request requestOfTheIdp(Session session, String relayState) {
    Request request = mock(Request.class);
    when(request.getContextPath()).thenReturn("/portal");
    when(request.getParameter(GeneralConstants.SAML_RESPONSE_KEY)).thenReturn("PHJlc3BvbnNlLz4=");
    when(request.getParameter(GeneralConstants.RELAY_STATE)).thenReturn(relayState);
    when(request.getSessionInternal(true)).thenReturn(session);
    return request;
  }

  private static Request requestOfTheUser(Session session, String method, String uri, String query) {
    SavedRequest saved = new SavedRequest();
    saved.setMethod(method);
    saved.setRequestURI(uri);
    saved.setDecodedRequestURI(uri);
    saved.setQueryString(query);
    when(session.getNote(Constants.FORM_REQUEST_NOTE)).thenReturn(saved);
    Request request = mock(Request.class);
    when(request.getContextPath()).thenReturn("/portal");
    when(request.getSessionInternal(false)).thenReturn(session);
    return request;
  }

  @Test
  public void theRequestOfTheUserSurvivesTheLossOfTheSessionCookie() {
    String uri = "/portal/sso";
    String query = "initialURI=/portal/g/:spaces:x/wiki";
    String id = valve.rememberTarget(requestOfTheUser(mock(Session.class), "GET", uri, query));
    assertNotNull(id);

    // the new session of the POST knows nothing of the request
    Session newSession = mock(Session.class);
    valve.restoreTargetOfTheLostSession(requestOfTheIdp(newSession, id));

    ArgumentCaptor<SavedRequest> restored = ArgumentCaptor.forClass(SavedRequest.class);
    verify(newSession).setNote(eq(Constants.FORM_REQUEST_NOTE), restored.capture());
    assertEquals("GET", restored.getValue().getMethod());
    assertEquals(uri, restored.getValue().getRequestURI());
    assertEquals(query, restored.getValue().getQueryString());
    // what the parent valve redirects to once the target is in the session
    when(newSession.getNote(Constants.FORM_REQUEST_NOTE)).thenReturn(restored.getValue());
    assertEquals(uri + "?" + query, valve.redirectOf(newSession));
  }

  @Test
  public void theParentValveRestoresTheTargetThroughTheHookBeforeItReadsTheAnswer() {
    String id = valve.rememberTarget(requestOfTheUser(mock(Session.class), "GET", "/portal/dologin", "initialURI=/portal/dw/tasks"));
    // a session that keeps its notes, like Tomcat's
    Map<String, Object> notes = new HashMap<>();
    Session newSession = mock(Session.class);
    doAnswer(call -> notes.put(call.getArgument(0), call.getArgument(1))).when(newSession).setNote(anyString(), any());
    when(newSession.getNote(anyString())).thenAnswer(call -> notes.get(call.<String> getArgument(0)));
    Request request = requestOfTheIdp(newSession, id);
    when(request.getSessionInternal(false)).thenReturn(newSession);
    Context context = mock(Context.class);
    when(request.getContext()).thenReturn(context);

    // the parent valve asks matchRequest first, then reads the answer, which a mock request cannot give: only the
    // order matters
    assertThrows(RuntimeException.class, () -> valve.authenticateThroughTheParent(request, mock(Response.class)));

    assertEquals("/portal/dologin?initialURI=/portal/dw/tasks", valve.redirectOf(newSession));
  }

  @Test
  public void theIdIsGoodForOneAnswer() {
    String id = valve.rememberTarget(requestOfTheUser(mock(Session.class), "GET", "/portal/sso", null));
    valve.restoreTargetOfTheLostSession(requestOfTheIdp(mock(Session.class), id));

    Session replay = mock(Session.class);
    valve.restoreTargetOfTheLostSession(requestOfTheIdp(replay, id));

    verify(replay, never()).setNote(eq(Constants.FORM_REQUEST_NOTE), any());
  }

  @Test
  public void aSessionThatKeptItsSavedRequestIsLeftAlone() {
    String id = valve.rememberTarget(requestOfTheUser(mock(Session.class), "GET", "/portal/sso", null));

    Session kept = mock(Session.class);
    when(kept.getNote(Constants.FORM_REQUEST_NOTE)).thenReturn(new SavedRequest());
    valve.restoreTargetOfTheLostSession(requestOfTheIdp(kept, id));

    verify(kept, never()).setNote(eq(Constants.FORM_REQUEST_NOTE), any());
  }

  @Test
  public void aSessionThatKeptItsSavedRequestIsLeftAloneBeforeAnyParameterIsRead() {
    Session kept = mock(Session.class);
    when(kept.getNote(Constants.FORM_REQUEST_NOTE)).thenReturn(new SavedRequest());
    Request request = mock(Request.class);
    when(request.getSessionInternal(false)).thenReturn(kept);

    valve.restoreTargetOfTheLostSession(request);

    verify(request, never()).getParameter(anyString());
    verify(kept, never()).setNote(anyString(), any());
  }

  @Test
  public void anIdThatTheValveDidNotGiveIsIgnored() {
    Session session = mock(Session.class);

    valve.restoreTargetOfTheLostSession(requestOfTheIdp(session, "/portal/g/:spaces:x"));
    valve.restoreTargetOfTheLostSession(requestOfTheIdp(session, "https://evil.example/"));

    verify(session, never()).setNote(eq(Constants.FORM_REQUEST_NOTE), any());
  }

  @Test
  public void aRelayStateThatComesWithoutAnAnswerIsIgnored() {
    String id = valve.rememberTarget(requestOfTheUser(mock(Session.class), "GET", "/portal/sso", null));
    Session session = mock(Session.class);
    Request request = requestOfTheIdp(session, id);
    when(request.getParameter(GeneralConstants.SAML_RESPONSE_KEY)).thenReturn(null);

    valve.restoreTargetOfTheLostSession(request);

    verify(session, never()).setNote(eq(Constants.FORM_REQUEST_NOTE), any());
  }

  @Test
  public void aRequestThatIsNotAGetIsNotKept() {
    assertNull(valve.rememberTarget(requestOfTheUser(mock(Session.class), "POST", "/portal/sso", null)));
  }

  @Test
  public void aTargetOutsideTheApplicationIsNotKept() {
    assertNull(valve.rememberTarget(requestOfTheUser(mock(Session.class), "GET", "//evil.example/portal", null)));
  }

  @Test
  public void nothingIsKeptWithoutASavedRequest() {
    Request request = mock(Request.class);
    when(request.getContextPath()).thenReturn("/portal");
    when(request.getSessionInternal(false)).thenReturn(mock(Session.class));

    assertNull(valve.rememberTarget(request));
  }


  // The id reaches the IDP as the RelayState of the request

  private static final String AUTHN_REQUEST_XML = "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_1\"/>";

  private static Document parse(String xml) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    return factory.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
  }

  private String relayStateSentToTheIdp(String requestXml, String destinationQueryStringWithSignature) throws Exception {
    Document document = parse(requestXml);
    Session session = mock(Session.class);
    SavedRequest saved = new SavedRequest();
    saved.setMethod("GET");
    saved.setRequestURI("/portal/sso");
    saved.setDecodedRequestURI("/portal/sso");
    saved.setQueryString("initialURI=/portal/g/:spaces:x");
    when(session.getNote(Constants.FORM_REQUEST_NOTE)).thenReturn(saved);
    Request request = mock(Request.class);
    when(request.getContextPath()).thenReturn("/portal");
    when(request.getSessionInternal(false)).thenReturn(session);
    Response response = mock(Response.class);
    ByteArrayOutputStream page = new ByteArrayOutputStream();
    when(response.getOutputStream()).thenReturn(new ServletOutputStream() {
      @Override
      public void write(int b) {
        page.write(b);
      }

      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void setWriteListener(WriteListener listener) {
        // not used
      }
    });

    valve.sendRequestToIDP("https://idp.example/sso", document, "fromTheHandler", request, response, true,
                           destinationQueryStringWithSignature);

    Matcher relayState = Pattern.compile("NAME=\"RelayState\"\\s+VALUE=\"([^\"]*)\"", Pattern.CASE_INSENSITIVE).matcher(page.toString(StandardCharsets.UTF_8));
    return relayState.find() ? relayState.group(1) : null;
  }

  @Test
  public void theAuthnRequestToTheIdpCarriesTheIdOfTheTarget() throws Exception {
    String id = relayStateSentToTheIdp(AUTHN_REQUEST_XML, null);

    assertNotNull(id);
    assertNotEquals("fromTheHandler", id);
    SamlRelayTarget target = valve.relayStates.take(id);
    assertEquals("/portal/sso", target.requestURI());
    assertEquals("initialURI=/portal/g/:spaces:x", target.queryString());
  }

  @Test
  public void aRequestThatIsNotAnAuthnRequestKeepsItsRelayState() throws Exception {
    String logout = "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_2\"/>";

    assertEquals("fromTheHandler", relayStateSentToTheIdp(logout, null));
  }

  @Test
  public void anAjaxRequestKeepsNothing() throws Exception {
    Request request = mock(Request.class);
    when(request.getHeader(GeneralConstants.HTTP_HEADER_X_REQUESTED_WITH)).thenReturn("XMLHttpRequest");
    Response response = mock(Response.class);

    valve.sendRequestToIDP("https://idp.example/sso", parse(AUTHN_REQUEST_XML), "fromTheHandler", request, response, true, null);

    verify(request, never()).getSessionInternal(false);
  }

  @Test
  public void aSignedQueryStringOfTheRedirectBindingKeepsItsRelayState() throws Exception {

    // the signature covers the RelayState: nothing is kept, nothing is changed
    Document document = parse(AUTHN_REQUEST_XML);
    Request request = mock(Request.class);
    when(request.getSessionInternal(false)).thenReturn(mock(Session.class));
    Response response = mock(Response.class);
    SamlServiceProviderAuthenticator redirecting = new SamlServiceProviderAuthenticator() {
      @Override
      protected String getBinding() {
        return "REDIRECT";
      }
    };

    redirecting.sendRequestToIDP("https://idp.example/sso", document, "fromTheHandler", request, response, true,
                           "SAMLRequest=x&RelayState=fromTheHandler&SigAlg=y&Signature=z");

    verify(request, never()).getSessionInternal(false);
  }


  @Test
  public void theCacheServiceDoesNotComeFromTheContainerOfTheThread() {
    PortalContainer leftOver = mock(PortalContainer.class);
    when(leftOver.getComponentInstanceOfType(CacheService.class)).thenReturn(cacheService);
    ExoContainerContext.setCurrentContainer(leftOver);
    try {
      // a worker thread keeps the container of the last request it served: the valve reads its own servlet context
      assertNull(new SamlServiceProviderAuthenticator().cacheService());
    } finally {
      ExoContainerContext.setCurrentContainer(null);
    }
  }

  /** The valve with the cache service of the test, the POST binding, and a view on what the parent redirects to. */
  static class TestValve extends SamlServiceProviderAuthenticator {
    private final CacheService cacheService;

    TestValve(CacheService cacheService) {
      this.cacheService = cacheService;
    }

    @Override
    protected String getBinding() {
      return "POST";
    }

    @Override
    CacheService cacheService() {
      return cacheService;
    }

    String redirectOf(Session session) {
      return savedRequestURL(session);
    }

    /** The public entry of the parent valve, which reaches its private authenticate on every parent. */
    boolean authenticateThroughTheParent(Request request, Response response) throws IOException {
      return authenticate(request, response);
    }
  }

}
