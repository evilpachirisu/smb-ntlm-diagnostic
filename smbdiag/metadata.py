"""Pure NTLM metadata parsing. Never returns identity or response bytes."""
import struct
from impacket import ntlm
from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp, TypesMech

ESS = 0x00080000
SIGNATURE = b'NTLMSSP\x00'


class InvalidToken(ValueError):
    pass


def unwrap(blob):
    if blob.startswith(SIGNATURE):
        return blob, True
    try:
        if blob[:1] == b'\x60':
            item = SPNEGO_NegTokenInit(blob)
            if not item['MechTypes'] or item['MechTypes'][0] != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']:
                raise InvalidToken()
            return item['MechToken'], False
        if blob[:1] == b'\xa1':
            return SPNEGO_NegTokenResp(blob)['ResponseToken'], False
    except Exception:
        raise InvalidToken() from None
    raise InvalidToken()


def security_buffer(token, offset, minimum):
    length, maximum, start = struct.unpack_from('<HHI', token, offset)
    if maximum < length or (length and (start < minimum or start + length > len(token))):
        raise InvalidToken()
    return token[start:start + length] if length else b''


def v2_blob_valid(response):
    # NT proof (16) + fixed blob header (28) + AV_EOL (4).
    # Accept the optional four zero bytes after AV_EOL as well.
    if len(response) < 48 or response[16:24] != b'\x01\x01' + b'\x00' * 6:
        return False
    if response[40:44] != b'\x00' * 4:
        return False
    pos = 44
    while pos + 4 <= len(response):
        avid, length = struct.unpack_from('<HH', response, pos)
        pos += 4
        if avid == 0:
            return length == 0 and response[pos:] in (b'', b'\x00' * 4)
        if pos + length > len(response):
            return False
        pos += length
    return False


def classify(lm, nt, flags, negotiated_ess):
    if not nt:
        return 'empty_or_anonymous', 'no_nt_response'
    if v2_blob_valid(nt):
        return 'NTLMv2', 'blob_structure_only'
    if len(nt) != 24:
        return 'unknown', 'unrecognized_nt_response_structure'
    if negotiated_ess is None:
        return 'unknown', 'missing_type1_or_type2'
    if negotiated_ess and flags & ESS:
        if len(lm) == 24 and lm[8:] == b'\x00' * 16:
            return 'NTLMv1-ESS', 'length_padding_and_ess_only'
        return 'unknown', 'ess_response_inconsistent'
    if not negotiated_ess and not flags & ESS:
        return 'NTLMv1', 'length_and_flags_only'
    return 'unknown', 'ess_flags_inconsistent'


def inspect(token, negotiated_ess=None):
    try:
        if not token.startswith(SIGNATURE) or len(token) < 12:
            raise InvalidToken()
        kind = struct.unpack_from('<I', token, 8)[0]
        sizes = {1: 32, 2: 48, 3: 64}
        if kind not in sizes or len(token) < sizes[kind]:
            raise InvalidToken()
        offset = {1: 12, 2: 20, 3: 60}[kind]
        flags = struct.unpack_from('<I', token, offset)[0]
        result = {'message_type': kind, 'flags_hex': f'0x{flags:08x}',
                  'flag_names': sorted(name for name, value in vars(ntlm).items()
                                       if (name.startswith('NTLMSSP_NEGOTIATE_') or name in
                                           ('NTLMSSP_REQUEST_TARGET', 'NTLMSSP_TARGET_TYPE_DOMAIN',
                                            'NTLMSSP_TARGET_TYPE_SERVER', 'NTLM_NEGOTIATE_OEM'))
                                       and isinstance(value, int) and value and flags & value == value),
                  'ess': bool(flags & ESS)}
        if kind == 1:
            for off in (16, 24):
                security_buffer(token, off, 32)
        elif kind == 2:
            for off in (12, 40):
                security_buffer(token, off, 48)
        else:
            parts = [security_buffer(token, off, 64) for off in (12, 20, 28, 36, 44, 52)]
            lm, nt = parts[:2]
            form, basis = classify(lm, nt, flags, negotiated_ess)
            result.update(response_format=form, classification_basis=basis,
                          lm_response_length=len(lm), nt_response_length=len(nt),
                          negotiated_ess=negotiated_ess)
        return result
    except (ValueError, struct.error, IndexError):
        raise InvalidToken() from None
