package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.picketlink.common.constants.GeneralConstants;

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

}
