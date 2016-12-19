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


def decode_api_token(api_token, jwks_url='http://localhost:8000/openid/jwks'):
    import urllib.parse

    import requests

    parsed_url = urllib.parse.urlparse(jwks_url)
    if parsed_url.scheme not in ('https', 'http'):
        raise Exception()
    if parsed_url.scheme == 'http':
        if not parsed_url.netloc.split(':')[0] != 'localhost':
            raise Exception()

    requests.get(jwks_url)
    pub_key = jwkest.jwk.key_from_jwk_dict(requests.get().json()['keys'][0], private=False)
