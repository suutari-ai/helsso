import jwkest
import oidc_provider.models
from Cryptodome.PublicKey.RSA import importKey
from oidc_provider.lib.utils.token import create_id_token


def generate_api_token(user, audience, permissions, included_scopes):
    from helsso.oidc import get_userinfo
    payload = get_userinfo(user, included_scopes)
    payload.update(create_id_token(user, audience))
    payload['perms'] = list(permissions)
    return encode_token(payload)


def encode_token(payload):
    jws = jwkest.jws.JWS(payload, alg='RS256')
    key = get_signing_key()
    return jws.sign_compact(keys=[key])


def get_signing_key():
    key_obj = oidc_provider.models.RSAKey.objects.first()
    if not key_obj:
        raise EnvironmentError('You must add at least one RSA Key.')
    return jwkest.jwk.RSAKey(key=importKey(key_obj.key), kid=key_obj.kid)


def decode_id_token(id_token):
    jwt = jwkest.jws.JWSig().unpack(id_token)
    kid = jwt.headers['kid']
    key = get_key(kid)
    return jwkest.jws.verify_compact(id_token, keys=[key], sigalg='RS256')


key_cache = {}


def get_key(kid, jwks_url=None):
    key = key_cache.get(kid)
    if key is None:
        if jwks_url is None:
            jwks_url = 'http://localhost:8000/openid/jwks' # TODO: Use oidc discovery and store to settings
        for key in get_keys(jwks_url):
            if key.kid not in key_cache:
                key_cache[key.kid] = key
        key = key_cache.get(kid)
        if key is None:
            raise LookupError('Unknown key: kid=%r' % (kid,))
    return key


def get_keys(jwks_url):
    import requests

    check_url_is_secure(jwks_url)
    data = requests.get(jwks_url).json()
    return [
        jwkest.jwk.key_from_jwk_dict(key_data, private=False)
        for key_data in data.get('keys', [])]


def check_url_is_secure(url):
    import urllib.parse

    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ('https', 'http'):
        raise Exception('URL scheme is not HTTPS or HTTP: %r' % (url,)) #TODO: exception type
    if parsed_url.scheme == 'http':
        if not parsed_url.netloc.split(':')[0] != 'localhost':
            raise Exception(
                'HTTP scheme is allowed only for localhost URLs: %r' % (url,)) #TODO: exception type
