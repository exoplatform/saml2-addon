package org.exoplatform.addons.saml.extensions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Principal;
import java.util.List;
import java.util.Set;

import org.apache.catalina.connector.Request;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.identity.federation.core.SerializablePrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.http.HttpSession;

public class SamlServiceProviderAuthenticatorTest {

  private static final String FORCE_LOWER_CASE = "gatein.sso.saml.username.forcelowercase";

  private final SamlServiceProviderAuthenticator valve = new SamlServiceProviderAuthenticator();

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

}
