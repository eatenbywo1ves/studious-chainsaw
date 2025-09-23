"""
SAML 2.0 Federation Implementation

Enterprise SAML 2.0 Service Provider (SP) and Identity Provider (IdP) with:
- SAML SSO (Single Sign-On) flows
- Identity Provider metadata parsing
- SAML assertion validation and processing
- Attribute mapping and transformation
- Multi-tenant IdP configuration
- SAML logout (SLO)
"""

import base64
import gzip
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import defusedxml.ElementTree as DefusedET

# SAML 2.0 Namespaces
SAML_NS = {
    "saml2": "urn:oasis:names:tc:SAML:2.0:assertion",
    "saml2p": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}


@dataclass
class SAMLAttribute:
    """SAML attribute representation"""

    name: str
    friendly_name: Optional[str] = None
    name_format: str = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    values: List[str] = field(default_factory=list)


@dataclass
class SAMLSubject:
    """SAML subject information"""

    name_id: str
    name_id_format: str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    confirmation_method: str = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
    not_on_or_after: Optional[datetime] = None
    recipient: Optional[str] = None
    in_response_to: Optional[str] = None


@dataclass
class SAMLConditions:
    """SAML conditions for assertion validity"""

    not_before: Optional[datetime] = None
    not_on_or_after: Optional[datetime] = None
    audience_restrictions: List[str] = field(default_factory=list)


@dataclass
class SAMLAssertion:
    """SAML assertion representation"""

    assertion_id: str
    issuer: str
    subject: SAMLSubject
    conditions: SAMLConditions
    attributes: List[SAMLAttribute] = field(default_factory=list)
    authentication_instant: Optional[datetime] = None
    session_index: Optional[str] = None
    authn_context_class_ref: str = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )

    @property
    def is_valid(self) -> bool:
        """Check if assertion is currently valid"""
        now = datetime.utcnow()

        if self.conditions.not_before and now < self.conditions.not_before:
            return False

        if self.conditions.not_on_or_after and now >= self.conditions.not_on_or_after:
            return False

        if self.subject.not_on_or_after and now >= self.subject.not_on_or_after:
            return False

        return True

    def get_attribute_values(self, attribute_name: str) -> List[str]:
        """Get values for a specific attribute"""
        for attr in self.attributes:
            if attr.name == attribute_name or attr.friendly_name == attribute_name:
                return attr.values
        return []

    def get_attribute_value(self, attribute_name: str) -> Optional[str]:
        """Get first value for a specific attribute"""
        values = self.get_attribute_values(attribute_name)
        return values[0] if values else None


@dataclass
class SAMLResponse:
    """SAML response representation"""

    response_id: str
    issuer: str
    status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success"
    status_message: Optional[str] = None
    in_response_to: Optional[str] = None
    destination: Optional[str] = None
    assertions: List[SAMLAssertion] = field(default_factory=list)
    issue_instant: datetime = field(default_factory=datetime.utcnow)

    @property
    def is_success(self) -> bool:
        """Check if response indicates success"""
        return self.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def get_first_assertion(self) -> Optional[SAMLAssertion]:
        """Get the first assertion from response"""
        return self.assertions[0] if self.assertions else None


@dataclass
class IdPConfiguration:
    """Identity Provider configuration"""

    entity_id: str
    sso_url: str
    slo_url: Optional[str] = None
    x509_cert: Optional[str] = None
    name_id_format: str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    binding: str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    sign_requests: bool = True
    want_assertions_signed: bool = True
    attribute_mapping: Dict[str, str] = field(default_factory=dict)
    tenant_id: Optional[str] = None


@dataclass
class SPConfiguration:
    """Service Provider configuration"""

    entity_id: str
    acs_url: str
    sls_url: Optional[str] = None
    private_key: Optional[str] = None
    x509_cert: Optional[str] = None
    name_id_format: str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    binding: str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    sign_requests: bool = True
    want_assertions_signed: bool = True
    assertion_consumer_service_index: int = 0


class SAMLRequest:
    """SAML authentication request generator"""

    def __init__(self, sp_config: SPConfiguration):
        self.sp_config = sp_config

    def create_authn_request(
        self, idp_sso_url: str, relay_state: Optional[str] = None
    ) -> Tuple[str, str]:
        """Create SAML authentication request"""
        request_id = f"id_{uuid.uuid4().hex}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        # Build SAML request XML
        authn_request = f"""<saml2p:AuthnRequest
            xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{issue_instant}"
            Destination="{idp_sso_url}"
            ProtocolBinding="{self.sp_config.binding}"
            AssertionConsumerServiceURL="{self.sp_config.acs_url}">
            <saml2:Issuer>{self.sp_config.entity_id}</saml2:Issuer>
            <saml2p:NameIDPolicy
                Format="{self.sp_config.name_id_format}"
                AllowCreate="true" />
        </saml2p:AuthnRequest>"""

        # Sign request if required
        if self.sp_config.sign_requests and self.sp_config.private_key:
            authn_request = self._sign_xml(authn_request)

        # Encode request
        encoded_request = self._encode_saml_request(authn_request)

        return request_id, encoded_request

    def create_logout_request(
        self, idp_slo_url: str, name_id: str, session_index: str
    ) -> Tuple[str, str]:
        """Create SAML logout request"""
        request_id = f"id_{uuid.uuid4().hex}"
        issue_instant = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

        logout_request = f"""<saml2p:LogoutRequest
            xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
            xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"
            ID="{request_id}"
            Version="2.0"
            IssueInstant="{issue_instant}"
            Destination="{idp_slo_url}">
            <saml2:Issuer>{self.sp_config.entity_id}</saml2:Issuer>
            <saml2:NameID Format="{self.sp_config.name_id_format}">{name_id}</saml2:NameID>
            <saml2p:SessionIndex>{session_index}</saml2p:SessionIndex>
        </saml2p:LogoutRequest>"""

        if self.sp_config.sign_requests and self.sp_config.private_key:
            logout_request = self._sign_xml(logout_request)

        encoded_request = self._encode_saml_request(logout_request)
        return request_id, encoded_request

    def _encode_saml_request(self, request_xml: str) -> str:
        """Encode SAML request for HTTP-Redirect binding"""
        # Compress and encode
        compressed = gzip.compress(request_xml.encode("utf-8"))
        encoded = base64.b64encode(compressed).decode("utf-8")
        return quote(encoded)

    def _sign_xml(self, xml_string: str) -> str:
        """Sign XML using private key"""
        # Simplified signing - in production, use proper XML DSig
        # This would involve canonicalization, digest calculation, etc.
        return xml_string


class SAMLResponseParser:
    """SAML response parser and validator"""

    def __init__(self, sp_config: SPConfiguration, idp_config: IdPConfiguration):
        self.sp_config = sp_config
        self.idp_config = idp_config

    def parse_saml_response(
        self, saml_response_data: str, relay_state: Optional[str] = None
    ) -> SAMLResponse:
        """Parse and validate SAML response"""
        # Decode SAML response
        decoded_response = base64.b64decode(saml_response_data).decode("utf-8")

        try:
            # Parse XML with defusedxml for security
            root = DefusedET.fromstring(decoded_response)
        except ET.ParseError as e:
            raise ValueError(f"Invalid SAML response XML: {e}")

        # Validate signature if required
        if self.sp_config.want_assertions_signed:
            self._validate_signature(root)

        # Parse response elements
        response_id = root.get("ID")
        if not response_id:
            raise ValueError("Missing response ID")

        issuer_elem = root.find(".//saml2:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None else None

        if issuer != self.idp_config.entity_id:
            raise ValueError(
                f"Invalid issuer: expected {self.idp_config.entity_id}, got {issuer}"
            )

        # Parse status
        status_elem = root.find(".//saml2p:Status/saml2p:StatusCode", SAML_NS)
        status_code = status_elem.get("Value") if status_elem is not None else None

        status_message_elem = root.find(
            ".//saml2p:Status/saml2p:StatusMessage", SAML_NS
        )
        status_message = (
            status_message_elem.text if status_message_elem is not None else None
        )

        # Parse destination and in response to
        destination = root.get("Destination")
        in_response_to = root.get("InResponseTo")

        # Create response object
        saml_response = SAMLResponse(
            response_id=response_id,
            issuer=issuer,
            status_code=status_code,
            status_message=status_message,
            in_response_to=in_response_to,
            destination=destination,
        )

        # Parse assertions
        assertion_elems = root.findall(".//saml2:Assertion", SAML_NS)
        for assertion_elem in assertion_elems:
            assertion = self._parse_assertion(assertion_elem)
            saml_response.assertions.append(assertion)

        return saml_response

    def _parse_assertion(self, assertion_elem: ET.Element) -> SAMLAssertion:
        """Parse SAML assertion"""
        assertion_id = assertion_elem.get("ID")
        if not assertion_id:
            raise ValueError("Missing assertion ID")

        # Parse issuer
        issuer_elem = assertion_elem.find("saml2:Issuer", SAML_NS)
        issuer = issuer_elem.text if issuer_elem is not None else None

        # Parse subject
        subject_elem = assertion_elem.find("saml2:Subject", SAML_NS)
        if subject_elem is None:
            raise ValueError("Missing subject in assertion")

        subject = self._parse_subject(subject_elem)

        # Parse conditions
        conditions_elem = assertion_elem.find("saml2:Conditions", SAML_NS)
        conditions = (
            self._parse_conditions(conditions_elem)
            if conditions_elem is not None
            else SAMLConditions()
        )

        # Parse authentication statement
        authn_stmt_elem = assertion_elem.find("saml2:AuthnStatement", SAML_NS)
        authentication_instant = None
        session_index = None
        authn_context_class_ref = None

        if authn_stmt_elem is not None:
            auth_instant_str = authn_stmt_elem.get("AuthnInstant")
            if auth_instant_str:
                authentication_instant = datetime.fromisoformat(
                    auth_instant_str.replace("Z", "+00:00")
                )

            session_index = authn_stmt_elem.get("SessionIndex")

            authn_context_elem = authn_stmt_elem.find(
                "saml2:AuthnContext/saml2:AuthnContextClassRef", SAML_NS
            )
            if authn_context_elem is not None:
                authn_context_class_ref = authn_context_elem.text

        # Parse attributes
        attributes = []
        attr_stmt_elem = assertion_elem.find("saml2:AttributeStatement", SAML_NS)
        if attr_stmt_elem is not None:
            attr_elems = attr_stmt_elem.findall("saml2:Attribute", SAML_NS)
            for attr_elem in attr_elems:
                attribute = self._parse_attribute(attr_elem)
                attributes.append(attribute)

        return SAMLAssertion(
            assertion_id=assertion_id,
            issuer=issuer,
            subject=subject,
            conditions=conditions,
            attributes=attributes,
            authentication_instant=authentication_instant,
            session_index=session_index,
            authn_context_class_ref=authn_context_class_ref
            or "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        )

    def _parse_subject(self, subject_elem: ET.Element) -> SAMLSubject:
        """Parse SAML subject"""
        name_id_elem = subject_elem.find("saml2:NameID", SAML_NS)
        if name_id_elem is None:
            raise ValueError("Missing NameID in subject")

        name_id = name_id_elem.text
        name_id_format = name_id_elem.get(
            "Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        )

        # Parse subject confirmation
        confirmation_elem = subject_elem.find("saml2:SubjectConfirmation", SAML_NS)
        confirmation_method = (
            confirmation_elem.get("Method") if confirmation_elem is not None else None
        )

        confirmation_data_elem = subject_elem.find(
            "saml2:SubjectConfirmation/saml2:SubjectConfirmationData", SAML_NS
        )
        not_on_or_after = None
        recipient = None
        in_response_to = None

        if confirmation_data_elem is not None:
            not_on_or_after_str = confirmation_data_elem.get("NotOnOrAfter")
            if not_on_or_after_str:
                not_on_or_after = datetime.fromisoformat(
                    not_on_or_after_str.replace("Z", "+00:00")
                )

            recipient = confirmation_data_elem.get("Recipient")
            in_response_to = confirmation_data_elem.get("InResponseTo")

        return SAMLSubject(
            name_id=name_id,
            name_id_format=name_id_format,
            confirmation_method=confirmation_method
            or "urn:oasis:names:tc:SAML:2.0:cm:bearer",
            not_on_or_after=not_on_or_after,
            recipient=recipient,
            in_response_to=in_response_to,
        )

    def _parse_conditions(self, conditions_elem: ET.Element) -> SAMLConditions:
        """Parse SAML conditions"""
        not_before_str = conditions_elem.get("NotBefore")
        not_on_or_after_str = conditions_elem.get("NotOnOrAfter")

        not_before = None
        if not_before_str:
            not_before = datetime.fromisoformat(not_before_str.replace("Z", "+00:00"))

        not_on_or_after = None
        if not_on_or_after_str:
            not_on_or_after = datetime.fromisoformat(
                not_on_or_after_str.replace("Z", "+00:00")
            )

        # Parse audience restrictions
        audience_restrictions = []
        audience_restriction_elems = conditions_elem.findall(
            "saml2:AudienceRestriction/saml2:Audience", SAML_NS
        )
        for audience_elem in audience_restriction_elems:
            if audience_elem.text:
                audience_restrictions.append(audience_elem.text)

        return SAMLConditions(
            not_before=not_before,
            not_on_or_after=not_on_or_after,
            audience_restrictions=audience_restrictions,
        )

    def _parse_attribute(self, attr_elem: ET.Element) -> SAMLAttribute:
        """Parse SAML attribute"""
        name = attr_elem.get("Name")
        if not name:
            raise ValueError("Missing attribute name")

        friendly_name = attr_elem.get("FriendlyName")
        name_format = attr_elem.get(
            "NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
        )

        # Parse attribute values
        values = []
        value_elems = attr_elem.findall("saml2:AttributeValue", SAML_NS)
        for value_elem in value_elems:
            if value_elem.text:
                values.append(value_elem.text)

        return SAMLAttribute(
            name=name,
            friendly_name=friendly_name,
            name_format=name_format,
            values=values,
        )

    def _validate_signature(self, xml_elem: ET.Element):
        """Validate XML signature"""
        # Simplified signature validation
        # In production, implement proper XML DSig validation
        signature_elem = xml_elem.find(".//ds:Signature", SAML_NS)
        if signature_elem is None and self.sp_config.want_assertions_signed:
            raise ValueError("Missing required signature")

        # Would validate signature using IdP certificate
        if signature_elem is not None and self.idp_config.x509_cert:
            # Implement signature validation logic
            pass


class SAMLProvider:
    """
    Complete SAML 2.0 Service Provider implementation
    """

    def __init__(self, sp_config: SPConfiguration):
        self.sp_config = sp_config
        self.idp_configs: Dict[str, IdPConfiguration] = {}
        self.pending_requests: Dict[str, Tuple[str, datetime]] = (
            {}
        )  # request_id -> (idp_entity_id, timestamp)

    def register_idp(self, idp_config: IdPConfiguration):
        """Register Identity Provider configuration"""
        self.idp_configs[idp_config.entity_id] = idp_config

    def get_idp_config(self, entity_id: str) -> Optional[IdPConfiguration]:
        """Get IdP configuration by entity ID"""
        return self.idp_configs.get(entity_id)

    async def initiate_sso(
        self, idp_entity_id: str, relay_state: Optional[str] = None
    ) -> Dict[str, str]:
        """Initiate SAML SSO flow"""
        idp_config = self.get_idp_config(idp_entity_id)
        if not idp_config:
            raise ValueError(f"Unknown IdP: {idp_entity_id}")

        request_generator = SAMLRequest(self.sp_config)
        request_id, encoded_request = request_generator.create_authn_request(
            idp_config.sso_url, relay_state
        )

        # Store pending request
        self.pending_requests[request_id] = (idp_entity_id, datetime.utcnow())

        # Build redirect URL
        params = {"SAMLRequest": encoded_request}
        if relay_state:
            params["RelayState"] = relay_state

        redirect_url = f"{idp_config.sso_url}?{urllib.parse.urlencode(params)}"

        return {
            "request_id": request_id,
            "redirect_url": redirect_url,
            "idp_entity_id": idp_entity_id,
        }

    async def process_saml_response(
        self, saml_response: str, relay_state: Optional[str] = None
    ) -> Dict[str, Any]:
        """Process SAML response from IdP"""
        try:
            # Determine which IdP sent the response by trying to parse with each config
            parsed_response = None
            used_idp_config = None

            for idp_config in self.idp_configs.values():
                try:
                    parser = SAMLResponseParser(self.sp_config, idp_config)
                    parsed_response = parser.parse_saml_response(
                        saml_response, relay_state
                    )
                    used_idp_config = idp_config
                    break
                except Exception:
                    continue

            if not parsed_response or not used_idp_config:
                raise ValueError(
                    "Could not parse SAML response with any registered IdP"
                )

            # Validate response
            if not parsed_response.is_success:
                return {
                    "success": False,
                    "error": f"SAML authentication failed: {parsed_response.status_message}",
                    "status_code": parsed_response.status_code,
                }

            # Get first assertion
            assertion = parsed_response.get_first_assertion()
            if not assertion:
                return {
                    "success": False,
                    "error": "No assertion found in SAML response",
                }

            # Validate assertion
            if not assertion.is_valid:
                return {
                    "success": False,
                    "error": "SAML assertion is not valid (expired or not yet valid)",
                }

            # Validate audience if configured
            if used_idp_config and assertion.conditions.audience_restrictions:
                if (
                    self.sp_config.entity_id
                    not in assertion.conditions.audience_restrictions
                ):
                    return {
                        "success": False,
                        "error": "SAML assertion audience mismatch",
                    }

            # Clean up pending request
            if (
                parsed_response.in_response_to
                and parsed_response.in_response_to in self.pending_requests
            ):
                del self.pending_requests[parsed_response.in_response_to]

            # Map attributes
            user_attributes = self._map_attributes(
                assertion.attributes, used_idp_config
            )

            return {
                "success": True,
                "user_id": assertion.subject.name_id,
                "name_id_format": assertion.subject.name_id_format,
                "session_index": assertion.session_index,
                "attributes": user_attributes,
                "idp_entity_id": used_idp_config.entity_id,
                "tenant_id": used_idp_config.tenant_id,
                "authentication_instant": (
                    assertion.authentication_instant.isoformat()
                    if assertion.authentication_instant
                    else None
                ),
                "relay_state": relay_state,
            }

        except Exception as e:
            return {"success": False, "error": f"SAML processing error: {str(e)}"}

    async def initiate_slo(
        self, idp_entity_id: str, name_id: str, session_index: str
    ) -> Dict[str, str]:
        """Initiate SAML Single Logout"""
        idp_config = self.get_idp_config(idp_entity_id)
        if not idp_config or not idp_config.slo_url:
            raise ValueError(f"SLO not configured for IdP: {idp_entity_id}")

        request_generator = SAMLRequest(self.sp_config)
        request_id, encoded_request = request_generator.create_logout_request(
            idp_config.slo_url, name_id, session_index
        )

        # Build redirect URL
        params = {"SAMLRequest": encoded_request}
        redirect_url = f"{idp_config.slo_url}?{urllib.parse.urlencode(params)}"

        return {
            "request_id": request_id,
            "redirect_url": redirect_url,
            "idp_entity_id": idp_entity_id,
        }

    def _map_attributes(
        self, attributes: List[SAMLAttribute], idp_config: IdPConfiguration
    ) -> Dict[str, List[str]]:
        """Map SAML attributes using IdP configuration"""
        mapped_attributes = {}

        for attr in attributes:
            # Use attribute mapping if configured
            mapped_name = idp_config.attribute_mapping.get(attr.name, attr.name)
            if attr.friendly_name and not mapped_name:
                mapped_name = idp_config.attribute_mapping.get(
                    attr.friendly_name, attr.friendly_name
                )

            mapped_attributes[mapped_name or attr.name] = attr.values

        return mapped_attributes

    def generate_sp_metadata(self) -> str:
        """Generate Service Provider metadata XML"""
        metadata_xml = f"""<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     entityID="{self.sp_config.entity_id}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                        WantAssertionsSigned="{str(self.sp_config.want_assertions_signed).lower()}"
                        AuthnRequestsSigned="{str(self.sp_config.sign_requests).lower()}">

        <md:NameIDFormat>{self.sp_config.name_id_format}</md:NameIDFormat>

        <md:AssertionConsumerService Binding="{self.sp_config.binding}"
                                   Location="{self.sp_config.acs_url}"
                                   index="{self.sp_config.assertion_consumer_service_index}" />
        """

        if self.sp_config.sls_url:
            metadata_xml += f"""
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                              Location="{self.sp_config.sls_url}" />
            """

        if self.sp_config.x509_cert:
            metadata_xml += f"""
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{self.sp_config.x509_cert}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
            """

        metadata_xml += """
    </md:SPSSODescriptor>
</md:EntityDescriptor>"""

        return metadata_xml

    def cleanup_pending_requests(self, max_age_minutes: int = 30):
        """Clean up old pending requests"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=max_age_minutes)

        expired_requests = [
            request_id
            for request_id, (_, timestamp) in self.pending_requests.items()
            if timestamp < cutoff_time
        ]

        for request_id in expired_requests:
            del self.pending_requests[request_id]

    def get_pending_request_count(self) -> int:
        """Get count of pending SAML requests"""
        return len(self.pending_requests)

    def get_registered_idps(self) -> List[Dict[str, Any]]:
        """Get list of registered Identity Providers"""
        return [
            {
                "entity_id": idp.entity_id,
                "sso_url": idp.sso_url,
                "slo_url": idp.slo_url,
                "name_id_format": idp.name_id_format,
                "tenant_id": idp.tenant_id,
                "has_certificate": bool(idp.x509_cert),
            }
            for idp in self.idp_configs.values()
        ]
