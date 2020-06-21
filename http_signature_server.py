from base64 import b64decode
from collections import defaultdict
from datetime import datetime
import re
from typing import Callable, DefaultDict, List, Tuple, Union


def verify_headers(
        lookup_verifier: Callable[[str], Callable[[bytes, bytes], bool]],
        max_skew: int, method: str, path: str,
        headers: Tuple[Tuple[str, str], ...]
    ) \
        -> Union[
            Tuple[str, Tuple[None, None]],
            Tuple[None, Tuple[str, Tuple[Tuple[str, str], ...]]]]:
    now = int(datetime.now().timestamp())

    #########################
    # Ensure signature header

    try:
        sig_header = next(value for key, value in headers if key.lower() == 'signature').strip()
    except StopIteration:
        return 'Missing signature header', (None, None)

    #############################
    # Ensure is of correct format

    is_sig = re.match(r'^(([a-zA-Z]+=(("[^"]*")|\d+))(, (?=[a-zA-Z])|$))*$', sig_header)
    if not is_sig:
        return 'Invalid signature header', (None, None)

    #################################
    # Ensure have required parameters

    param_key_values = re.findall(r'([a-zA-Z]+)=(?:(?:"([^"]*)")|(\d+))', sig_header)
    params = dict(((key, (v_str or v_num)) for key, v_str, v_num in param_key_values))
    if len(param_key_values) != len(params):
        return 'Repeated parameter', (None, None)

    try:
        key_id_param = params['keyId']
    except KeyError:
        return f'Missing keyId parameter', (None, None)

    try:
        headers_param = params['headers']
    except KeyError:
        return f'Missing headers parameter', (None, None)

    try:
        signature_param = params['signature']
    except KeyError:
        return f'Missing signature parameter', (None, None)

    try:
        created_param = params['created']
    except KeyError:
        return f'Missing created parameter', (None, None)

    try:
        created = int(created_param)
    except ValueError:
        return 'Invalid created paramater', (None, None)

    ################################
    # Ensure time skew not too large

    if abs(now - created) > max_skew:
        return 'Created skew too large', (None, None)

    ########################################
    # Ensure required claimed-signed headers

    claimed_signed_headers = re.findall(r'\S+', headers_param)
    claimed_signed_headers_set = set(claimed_signed_headers)

    if len(claimed_signed_headers) != len(claimed_signed_headers_set):
        return 'Repeated signed header', (None, None)

    if '(created)' not in claimed_signed_headers_set:
        return 'Unsigned (created) pseudo-header', (None, None)

    if '(request-target)' not in claimed_signed_headers_set:
        return 'Unsigned (request-target) pseudo-header', (None, None)

    ###################################################
    # Ensure have values for all claimed-signed headers

    method_lower = method.lower()
    available_headers = (
        ('(created)', created_param),
        ('(request-target)', f'{method_lower} {path}'),
    ) + tuple(
        (key.lower(), value.strip()) for key, value in headers
    )
    available_headers_dict = dict(available_headers)
    for header in claimed_signed_headers:
        if header not in available_headers_dict:
            return f'Missing signed {header} header value', (None, None)

    ########################################
    # Ensure verifier corresponding to keyId

    matching_verifier = lookup_verifier(key_id_param)
    if not matching_verifier:
        return 'Unknown keyId', (None, None)

    ##################
    # Verify signature

    def signature_input() -> Tuple[Tuple[str, str], ...]:
        headers_lists: DefaultDict[str, List[str]] = defaultdict(list)
        for key, value in available_headers:
            headers_lists[key].append(value)
        return tuple((key, ', '.join(headers_lists[key])) for key in claimed_signed_headers)

    verified = matching_verifier(b64decode(signature_param), '\n'.join(
        f'{key}: {value}' for key, value in signature_input()
    ).encode('ascii'))

    if not verified:
        return 'Signature does not verify', (None, None)

    ##############################################
    # Generate key value pairs of verified headers

    def verified_headers() -> Tuple[Tuple[str, str], ...]:
        key_values = []
        for key, value in headers:
            if key.lower() in claimed_signed_headers_set:
                key_values.append((key, value))
        return tuple(key_values)

    return None, (key_id_param, verified_headers())
