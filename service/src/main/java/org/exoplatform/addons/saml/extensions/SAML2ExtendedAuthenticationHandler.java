package org.exoplatform.addons.saml.extensions;

import jakarta.servlet.http.HttpSession;
import org.picketlink.common.constants.GeneralConstants;
import org.picketlink.common.constants.JBossSAMLConstants;
import org.picketlink.common.constants.JBossSAMLURIConstants;
import org.picketlink.common.exceptions.ConfigurationException;
import org.picketlink.common.exceptions.ProcessingException;
import org.picketlink.common.exceptions.fed.AssertionExpiredException;
import org.picketlink.common.util.DocumentUtil;
import org.picketlink.common.util.StaxParserUtil;
import org.picketlink.common.util.StringUtil;
import org.picketlink.config.federation.SPType;
import org.picketlink.identity.federation.api.saml.v2.response.SAML2Response;
import org.picketlink.identity.federation.core.SerializablePrincipal;
import org.picketlink.identity.federation.core.parsers.saml.SAMLParser;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2Handler;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.core.saml.v2.util.AssertionUtil;
import org.picketlink.identity.federation.core.util.JAXPValidationUtil;
import org.picketlink.identity.federation.core.util.XMLEncryptionUtil;
import org.picketlink.identity.federation.saml.v2.assertion.AssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeStatementType;
import org.picketlink.identity.federation.saml.v2.assertion.AttributeType;
import org.picketlink.identity.federation.saml.v2.assertion.EncryptedAssertionType;
import org.picketlink.identity.federation.saml.v2.assertion.NameIDType;
import org.picketlink.identity.federation.saml.v2.assertion.StatementAbstractType;
import org.picketlink.identity.federation.saml.v2.assertion.SubjectType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2AuthenticationHandler;
import org.picketlink.identity.federation.web.interfaces.IRoleValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.picketlink.common.util.StringUtil.isNotNull;

public class SAML2ExtendedAuthenticationHandler extends SAML2AuthenticationHandler {
  private final SPExtendedAuthenticationHandler sp = new SPExtendedAuthenticationHandler();

  @Override
  public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException {
    if (request.getSAML2Object() instanceof ResponseType == false)
      return;

    if (getType() == HANDLER_TYPE.IDP) {
      super.handleStatusResponseType(request, response);
    } else {
      sp.handleStatusResponseType(request, response);
    }
  }

  private class SPExtendedAuthenticationHandler {

    public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response)
        throws ProcessingException {
      HTTPContext httpContext = (HTTPContext) request.getContext();
      ResponseType responseType = (ResponseType) request.getSAML2Object();

      checkDestination(responseType.getDestination(), getSPConfiguration().getServiceURL());

      List<ResponseType.RTChoiceType> assertions = responseType.getAssertions();
      if (assertions.size() == 0)
        throw logger.samlHandlerNoAssertionFromIDP();

      PrivateKey privateKey = (PrivateKey) request.getOptions().get(GeneralConstants.DECRYPTING_KEY);

      Object assertion = assertions.get(0).getEncryptedAssertion();
      if (assertion instanceof EncryptedAssertionType) {
        responseType = this.decryptAssertion(responseType, privateKey);
        assertion = responseType.getAssertions().get(0).getAssertion();
      }
      if (assertion == null) {
        assertion = assertions.get(0).getAssertion();
      }

      request.addOption(GeneralConstants.ASSERTION, assertion);

      Principal userPrincipal = handleSAMLResponse(responseType, response);
      if (userPrincipal == null) {
        response.setError(403, "User Principal not determined: Forbidden");
      } else {
        HttpSession session = httpContext.getRequest().getSession(false);

        // add the principal to the session
        session.setAttribute(GeneralConstants.PRINCIPAL_ID, userPrincipal);

        Document responseDocument = request.getRequestDocument();
        Element assertionElement =
            DocumentUtil.getChildElement(responseDocument.getDocumentElement(),
                                         new QName(JBossSAMLConstants.ASSERTION.get()));

        if (assertionElement != null) {
          try {
            Document assertionDocument = DocumentUtil.createDocument();
            Node clonedAssertion = assertionElement.cloneNode(true);

            assertionDocument.adoptNode(clonedAssertion);
            assertionDocument.appendChild(clonedAssertion);

            String assertionAttributeName = (String) handlerConfig
                .getParameter(GeneralConstants.ASSERTION_SESSION_ATTRIBUTE_NAME);

            if (assertionAttributeName != null) {
              session.setAttribute(assertionAttributeName, assertionDocument);
            }

            session.setAttribute(GeneralConstants.ASSERTION_SESSION_ATTRIBUTE_NAME, assertionDocument);
          } catch (ConfigurationException e) {
            throw new ProcessingException("Could not store assertion document into session.", e);
          }
        }
      }
    }


    private ResponseType decryptAssertion(ResponseType responseType, PrivateKey privateKey) throws ProcessingException {
      if (privateKey == null)
        throw logger.nullArgumentError("privateKey");
      SAML2Response saml2Response = new SAML2Response();
      try {
        Document doc = saml2Response.convert(responseType);

        Element enc = DocumentUtil.getElement(doc, new QName(JBossSAMLConstants.ENCRYPTED_ASSERTION.get()));
        if (enc == null)
          throw logger.samlHandlerNullEncryptedAssertion();
        String oldID = enc.getAttribute(JBossSAMLConstants.ID.get());
        Document newDoc = DocumentUtil.createDocument();
        Node importedNode = newDoc.importNode(enc, true);
        newDoc.appendChild(importedNode);

        Element decryptedDocumentElement = XMLEncryptionUtil.decryptElementInDocument(newDoc, privateKey);
        SAMLParser parser = new SAMLParser();

        JAXPValidationUtil.checkSchemaValidation(decryptedDocumentElement);
        AssertionType assertion = (AssertionType) parser.parse(StaxParserUtil.getXMLEventReader(DocumentUtil
                                                                                                    .getNodeAsStream(decryptedDocumentElement)));

        responseType.replaceAssertion(oldID, new ResponseType.RTChoiceType(assertion));
        return responseType;
      } catch (Exception e) {
        throw logger.processingError(e);
      }
    }

    private Principal handleSAMLResponse(ResponseType responseType, SAML2HandlerResponse response)
        throws ProcessingException {
      if (responseType == null)
        throw logger.nullArgumentError("response type");

      StatusType statusType = responseType.getStatus();
      if (statusType == null)
        throw logger.nullArgumentError("Status Type from the IDP");

      String statusValue = statusType.getStatusCode().getValue().toASCIIString();
      if (JBossSAMLURIConstants.STATUS_SUCCESS.get().equals(statusValue) == false)
        throw logger.samlHandlerIDPAuthenticationFailedError();

      List<ResponseType.RTChoiceType> assertions = responseType.getAssertions();
      if (assertions.size() == 0)
        throw logger.samlHandlerNoAssertionFromIDP();

      AssertionType assertion = assertions.get(0).getAssertion();
      // Check for validity of assertion
      boolean expiredAssertion;
      try {
        String skew = (String) handlerConfig.getParameter(SAML2Handler.CLOCK_SKEW_MILIS);
        if (isNotNull(skew)) {
          long skewMilis = Long.parseLong(skew);
          expiredAssertion = AssertionUtil.hasExpired(assertion, skewMilis);
        } else
          expiredAssertion = AssertionUtil.hasExpired(assertion);
      } catch (ConfigurationException e) {
        throw new ProcessingException(e);
      }
      if (expiredAssertion) {
        AssertionExpiredException aee = new AssertionExpiredException();
        aee.setId(assertion.getID());
        throw logger.assertionExpiredError(aee);
      }

      if (!AssertionUtil.isAudience(assertion, getSPConfiguration())) {
        throw logger.samlAssertionWrongAudience(getSPConfiguration().getServiceURL());
      }

      SubjectType subject = assertion.getSubject();
      /*
       * JAXBElement<NameIDType> jnameID = (JAXBElement<NameIDType>) subject.getContent().get(0); NameIDType nameID =
       * jnameID.getValue();
       */
      if (subject == null)
        throw logger.nullValueError("Subject in the assertion");

      SubjectType.STSubType subType = subject.getSubType();
      if (subType == null)
        throw logger.nullValueError("Unable to find subtype via subject");
      NameIDType nameID = (NameIDType) subType.getBaseID();

      if (nameID == null)
        throw logger.nullValueError("Unable to find username via subject");

      String userName = nameID.getValue();
      if (!Boolean.parseBoolean((String)handlerConfig.getParameter("USE_NAMEID"))) {
        Set<StatementAbstractType> statements = assertion.getStatements();
        for (StatementAbstractType statement : statements) {
          if (statement instanceof AttributeStatementType attributeStatement) {
            List<AttributeStatementType.ASTChoiceType> attList = attributeStatement.getAttributes();
            for (AttributeStatementType.ASTChoiceType obj : attList) {
              AttributeType attr = obj.getAttribute();
              if ((attr.getFriendlyName() != null && attr.getFriendlyName().equals(handlerConfig.getParameter("SUBJECT_ATTRIBUTE"))) ||
                  (attr.getName() != null && attr.getName().equals(handlerConfig.getParameter("SUBJECT_ATTRIBUTE")))) {
                if (attr.getAttributeValue() != null) {
                  userName = (String) attr.getAttributeValue().get(0);
                }
              }
            }
          }
        }
      }

      List<String> roles = new ArrayList<>();

      // Let us get the roles
      Set<StatementAbstractType> statements = assertion.getStatements();
      for (StatementAbstractType statement : statements) {
        if (statement instanceof AttributeStatementType attributeStatement) {
          roles.addAll(getRoles(attributeStatement));
        }
      }

      response.setRoles(roles);

      Principal principal = new SerializablePrincipal(userName);

      if (handlerChainConfig.getParameter(GeneralConstants.ROLE_VALIDATOR_IGNORE) == null) {
        // Validate the roles
        IRoleValidator roleValidator = (IRoleValidator) handlerChainConfig
            .getParameter(GeneralConstants.ROLE_VALIDATOR);
        if (roleValidator == null)
          throw logger.nullValueError("Role Validator");

        boolean validRole = roleValidator.userInRole(principal, roles);

        if (!validRole) {
          logger.trace("Invalid role: " + roles);
          principal = null;
        }
      }
      return principal;
    }

    /**
     * Get the roles from the attribute statement
     *
     * @param attributeStatement
     *
     * @return
     */
    private List<String> getRoles(AttributeStatementType attributeStatement) {
      List<String> roles = new ArrayList<String>();

      // PLFED-141: Disable role picking from IDP response
      if (handlerConfig.containsKey(DISABLE_ROLE_PICKING)) {
        String val = (String) handlerConfig.getParameter(DISABLE_ROLE_PICKING);
        if (isNotNull(val) && "true".equalsIgnoreCase(val))
          return roles;
      }

      // PLFED-140: which of the attribute statements represent roles?
      List<String> roleKeys = new ArrayList<String>();

      if (handlerConfig.containsKey(ROLE_KEY)) {
        String roleKey = (String) handlerConfig.getParameter(ROLE_KEY);
        if (isNotNull(roleKey)) {
          roleKeys.addAll(StringUtil.tokenize(roleKey));
        }
      }

      List<AttributeStatementType.ASTChoiceType> attList = attributeStatement.getAttributes();
      for (AttributeStatementType.ASTChoiceType obj : attList) {
        AttributeType attr = obj.getAttribute();
        if (roleKeys.size() > 0) {
          if (!roleKeys.contains(attr.getName()))
            continue;
        }
        List<Object> attributeValues = attr.getAttributeValue();
        if (attributeValues != null) {
          for (Object attrValue : attributeValues) {
            if (attrValue instanceof String) {
              roles.add((String) attrValue);
            } else if (attrValue instanceof Node) {
              Node roleNode = (Node) attrValue;
              roles.add(roleNode.getFirstChild().getNodeValue());
            } else
              throw logger.unsupportedRoleType(attrValue);
          }
        }
      }
      return roles;
    }

    private SPType getSPConfiguration() {
      SPType spConfiguration = (SPType) handlerChainConfig.getParameter(GeneralConstants.CONFIGURATION);

      if (spConfiguration == null) {
        throw logger.samlHandlerServiceProviderConfigNotFound();
      }

      return spConfiguration;
    }
  }
}
