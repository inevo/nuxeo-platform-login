/*
 * (C) Copyright 2014 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     Nelson Silva <nelson.silva@inevo.pt>
 */
package org.nuxeo.ecm.platform.auth.saml.binding;

import org.apache.velocity.VelocityContext;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.ws.transport.http.HTTPTransport;

import java.util.HashMap;
import java.util.Map;

/**
 * HTTP Post Binding
 *
 * @since 6.0
 */
public class HTTPPostBinding extends SAMLBinding {

    public static final String SAML_REQUEST = "SAMLRequest";

    public static final String SAML_RESPONSE = "SAMLResponse";

    public static final String RELAY_STATE = "RelayState";

    public static class HTTPPostParamsEncoder extends HTTPPostEncoder {

        private Map<String, String> postFields;

        public HTTPPostParamsEncoder() {
            super(null, null);
        }

        public void encode(MessageContext messageContext) throws MessageEncodingException {
            doEncode(messageContext);
            logEncodedMessage(messageContext);
        }

        @Override
        protected void doEncode(MessageContext messageContext) throws MessageEncodingException {
            SAMLMessageContext samlMsgCtx = (SAMLMessageContext) messageContext;

            SAMLObject outboundMessage = samlMsgCtx.getOutboundSAMLMessage();
            if (outboundMessage == null) {
                throw new MessageEncodingException("No outbound SAML message contained in message context");
            }
            String endpointURL = getEndpointURL(samlMsgCtx).buildURL();

            if (samlMsgCtx.getOutboundSAMLMessage() instanceof StatusResponseType) {
                ((StatusResponseType) samlMsgCtx.getOutboundSAMLMessage()).setDestination(endpointURL);
            }

            signMessage(samlMsgCtx);
            samlMsgCtx.setOutboundMessage(outboundMessage);

            postEncode(samlMsgCtx, endpointURL);
        }

        @Override
        protected void postEncode(SAMLMessageContext messageContext, String endpointURL) throws
        MessageEncodingException {
            VelocityContext context = new VelocityContext();

            populateVelocityContext(context, messageContext, endpointURL);

            postFields = new HashMap<>();
            postFields.put(SAML_REQUEST, (String) context.get(SAML_REQUEST));
            postFields.put(SAML_RESPONSE, (String) context.get(SAML_RESPONSE));
            postFields.put(RELAY_STATE, (String) context.get(RELAY_STATE));
        }
    }

    public HTTPPostBinding() {
        super(new HTTPPostDecoder(), new HTTPPostParamsEncoder());
    }

    private HTTPPostBinding(MessageDecoder decoder, MessageEncoder encoder) {
        super(decoder, encoder);
    }

    public boolean supports(InTransport transport) {
        if (transport instanceof HTTPInTransport) {
            HTTPTransport t = (HTTPTransport) transport;
            return "POST".equalsIgnoreCase(t.getHTTPMethod())
                    && (t.getParameterValue(SAML_REQUEST) != null || t.getParameterValue(SAML_RESPONSE) != null);
        } else {
            return false;
        }
    }

    public boolean supports(OutTransport transport) {
        return transport instanceof HTTPOutTransport;
    }

    public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }

    public Map<String, String> getPostParams(SAMLMessageContext context, Endpoint endpoint) throws SAMLException {
        try {
            context.setPeerEntityEndpoint(endpoint);
            encoder.encode(context);
        } catch (MessageEncodingException e) {
            throw new SAMLException("Failed to encode message.", e);
        }
        return ((HTTPPostParamsEncoder) encoder).postFields;
    }
}
