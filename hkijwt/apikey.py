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
    key_obj = oidc_provider.models.RSAKey.objects.first()
    if not key_obj:
        raise EnvironmentError('You must add at least one RSA Key.')
    key = jwkest.jwk.RSAKey(key=importKey(key_obj.key), kid=key_obj.kid)
    jws = jwkest.jws.JWS(payload, alg='RS256')
    return jws.sign_compact([key])
