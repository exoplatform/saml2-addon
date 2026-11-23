package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.apache.catalina.realm.GenericPrincipal;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.core.SerializablePrincipal;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

public class HybridSAML2LogoutFilterTest {

  private final HybridSAML2LogoutFilter filter = new HybridSAML2LogoutFilter();

  @Test
  public void localSessionGetsRegularLogout() throws Exception {
    HttpSession session = mock(HttpSession.class);
    HttpServletRequest request = logoutRequest(session);
    HttpServletResponse response = mock(HttpServletResponse.class);
    FilterChain chain = mock(FilterChain.class);

    assertFalse(HybridSAML2LogoutFilter.isSamlSession(request));
    filter.doFilter(request, response, chain);

    // Without the SAML session check, the parent filter starts the SAML
    // workflow and never calls the chain: blank page for the user
    verify(chain).doFilter(request, response);
    verify(session, never()).setAttribute(any(), any());
  }

  @Test
  public void samlSessionIsRecognized() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(GeneralConstants.PRINCIPAL_ID)).thenReturn(new Object());
    assertTrue(HybridSAML2LogoutFilter.isSamlSession(logoutRequest(session)));
  }

  @Test
  public void samlLogoutInProgressIsRecognized() {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(HybridSAML2LogoutFilter.SAML_LOGOUT_ATTRIBUTE)).thenReturn("/portal/logout");
    assertTrue(HybridSAML2LogoutFilter.isSamlSession(logoutRequest(session)));
  }

  @Test
  public void noSessionIsNotSaml() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    assertFalse(HybridSAML2LogoutFilter.isSamlSession(request));
  }

  private HttpServletRequest logoutRequest(HttpSession session) {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURI()).thenReturn("/portal/logout");
    when(request.getRemoteUser()).thenReturn("root");
    when(request.getSession()).thenReturn(session);
    when(request.getSession(false)).thenReturn(session);
    return request;
  }

  /** Records whether the request went to the SAML logout workflow of the parent filter */
  private static class RecordingFilter extends HybridSAML2LogoutFilter {
    private boolean delegated;

    @Override
    protected void delegateToSamlLogout(ServletRequest request, ServletResponse response, FilterChain chain) {
      delegated = true;
    }
  }

  @Test
  public void samlSessionGoesThroughTheSamlLogout() throws Exception {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(GeneralConstants.PRINCIPAL_ID)).thenReturn(new Object());
    HttpServletRequest request = logoutRequest(session);
    FilterChain chain = mock(FilterChain.class);
    RecordingFilter recording = new RecordingFilter();

    recording.doFilter(request, mock(HttpServletResponse.class), chain);

    assertTrue(recording.delegated, "the logout of a SAML session must go through the IDP");
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  public void samlLogoutInProgressGoesOnThroughTheSamlLogout() throws Exception {
    HttpSession session = mock(HttpSession.class);
    when(session.getAttribute(HybridSAML2LogoutFilter.SAML_LOGOUT_ATTRIBUTE)).thenReturn("/portal/logout");
    RecordingFilter recording = new RecordingFilter();

    recording.doFilter(logoutRequest(session), mock(HttpServletResponse.class), mock(FilterChain.class));

    assertTrue(recording.delegated);
  }

  @Test
  public void localSessionDoesNotGoThroughTheSamlLogout() throws Exception {
    RecordingFilter recording = new RecordingFilter();
    FilterChain chain = mock(FilterChain.class);
    HttpServletRequest request = logoutRequest(mock(HttpSession.class));
    HttpServletResponse response = mock(HttpServletResponse.class);

    recording.doFilter(request, response, chain);

    assertFalse(recording.delegated);
    verify(chain).doFilter(request, response);
  }

  @Test
  public void otherRequestsAreLeftToTheParentFilter() throws Exception {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURI()).thenReturn("/portal/dw");
    RecordingFilter recording = new RecordingFilter();

    recording.doFilter(request, mock(HttpServletResponse.class), mock(FilterChain.class));

    assertTrue(recording.delegated);
  }

  @Test
  public void aSamlPrincipalMarksASamlSessionThatLostItsMarker() throws Exception {
    // The valve of Tomcat signs the user back in to a new portal session: the principal of the SAML login comes back
    // with it, the marker of the old session does not
    HttpSession session = mock(HttpSession.class);
    HttpServletRequest request = logoutRequest(session);
    // the eXo username is not the subject the IDP sent: the IDP is asked to end the session of the subject
    SamlPrincipal principal = new SamlPrincipal("jdoe", List.of("users"), "John.Doe@corp.com");
    when(request.getUserPrincipal()).thenReturn(principal);
    FilterChain chain = mock(FilterChain.class);
    RecordingFilter recording = new RecordingFilter();

    recording.doFilter(request, mock(HttpServletResponse.class), chain);

    assertTrue(HybridSAML2LogoutFilter.isSamlSession(request));
    assertTrue(recording.delegated, "the logout of a SAML user must go through the IDP");
    // The SAML logout workflow reads the user from this attribute of the session: it is written back
    ArgumentCaptor<Object> marker = ArgumentCaptor.forClass(Object.class);
    verify(session).setAttribute(eq(GeneralConstants.PRINCIPAL_ID), marker.capture());
    SerializablePrincipal written = assertInstanceOf(SerializablePrincipal.class, marker.getValue());
    assertEquals("John.Doe@corp.com", written.getName());
    verify(chain, never()).doFilter(any(), any());
  }

  @Test
  public void aSamlPrincipalWithoutSessionIsStillSaml() {
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getUserPrincipal()).thenReturn(new SamlPrincipal("root", List.of()));
    assertTrue(HybridSAML2LogoutFilter.isSamlSession(request));
  }

  @Test
  public void anotherPrincipalWithoutMarkerKeepsTheRegularLogout() throws Exception {
    HttpServletRequest request = logoutRequest(mock(HttpSession.class));
    when(request.getUserPrincipal()).thenReturn(new GenericPrincipal("root", List.of("users")));
    FilterChain chain = mock(FilterChain.class);
    RecordingFilter recording = new RecordingFilter();
    HttpServletResponse response = mock(HttpServletResponse.class);

    recording.doFilter(request, response, chain);

    assertFalse(HybridSAML2LogoutFilter.isSamlSession(request));
    assertFalse(recording.delegated);
    verify(chain).doFilter(request, response);
  }

  @Test
  public void theMarkerOfASessionThatHasItIsLeftAlone() throws Exception {
    HttpSession session = mock(HttpSession.class);
    Object marker = new Object();
    when(session.getAttribute(GeneralConstants.PRINCIPAL_ID)).thenReturn(marker);
    HttpServletRequest request = logoutRequest(session);
    when(request.getUserPrincipal()).thenReturn(new SamlPrincipal("root", List.of()));

    new RecordingFilter().doFilter(request, mock(HttpServletResponse.class), mock(FilterChain.class));

    verify(session, never()).setAttribute(any(), any());
  }

  @Test
  public void theMarkerIsOnlyWrittenBackForTheLogout() throws Exception {
    HttpSession session = mock(HttpSession.class);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURI()).thenReturn("/portal/dw");
    when(request.getRemoteUser()).thenReturn("root");
    when(request.getSession()).thenReturn(session);
    when(request.getSession(false)).thenReturn(session);
    when(request.getUserPrincipal()).thenReturn(new SamlPrincipal("root", List.of()));

    new RecordingFilter().doFilter(request, mock(HttpServletResponse.class), mock(FilterChain.class));

    verify(session, never()).setAttribute(any(), any());
  }

  @Test
  public void theMarkerIsNotWrittenBackWithoutAnAuthenticatedUser() throws Exception {
    HttpSession session = mock(HttpSession.class);
    HttpServletRequest request = mock(HttpServletRequest.class);
    when(request.getRequestURI()).thenReturn("/portal/logout");
    when(request.getSession()).thenReturn(session);
    when(request.getSession(false)).thenReturn(session);
    when(request.getUserPrincipal()).thenReturn(new SamlPrincipal("root", List.of()));

    new RecordingFilter().doFilter(request, mock(HttpServletResponse.class), mock(FilterChain.class));

    verify(session, never()).setAttribute(any(), any());
  }

  @Test
  public void theMarkerIsWrittenBackBeforeTheSamlLogoutStarts() throws Exception {
    HttpSession session = mock(HttpSession.class);
    HttpServletRequest request = logoutRequest(session);
    SamlPrincipal principal = new SamlPrincipal("root", List.of());
    when(request.getUserPrincipal()).thenReturn(principal);
    List<Object> markerWhenTheLogoutStarts = new ArrayList<>();
    HybridSAML2LogoutFilter logoutFilter = new HybridSAML2LogoutFilter() {
      @Override
      protected void delegateToSamlLogout(ServletRequest servletRequest,
                                          ServletResponse servletResponse,
                                          FilterChain filterChain) {
        // the filter of the SAML workflow reads the user from the marker of the session: it must be there by now
        mockingDetails(session).getInvocations()
                               .stream()
                               .filter(i -> i.getMethod().getName().equals("setAttribute"))
                               .forEach(i -> markerWhenTheLogoutStarts.add(i.getArgument(1)));
      }
    };

    logoutFilter.doFilter(request, mock(HttpServletResponse.class), mock(FilterChain.class));

    assertEquals(1, markerWhenTheLogoutStarts.size());
    assertEquals("root", ((Principal) markerWhenTheLogoutStarts.get(0)).getName());
  }

}
