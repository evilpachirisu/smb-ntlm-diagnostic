"""Opt-in transient formatting of observed NetNTLM challenge/response evidence."""
from impacket.smbserver import outputToJohnFormat
from .metadata import security_buffer

FORMS = {'NTLMv1': 'NetNTLMv1', 'NTLMv1-ESS': 'NetNTLMv1 (ESS)', 'NTLMv2': 'NetNTLMv2'}


def format_response(token, challenge, response_format):
    """Use the existing classification; never format unknown/empty responses."""
    if response_format not in FORMS or not isinstance(challenge, bytes) or len(challenge) != 8:
        return None
    # The metadata parser already validated the Type 3 and all buffer boundaries.
    lm = security_buffer(token, 12, 64)
    nt = security_buffer(token, 20, 64)
    domain = security_buffer(token, 28, 64)
    user = security_buffer(token, 36, 64)
    result = outputToJohnFormat(challenge, user, domain, lm, nt)
    if isinstance(result, dict) and isinstance(result.get('hash_string'), str):
        return FORMS[response_format], result['hash_string']
    return None
