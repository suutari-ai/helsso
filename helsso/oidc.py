import logging

from django.utils.translation import ugettext_lazy as _
from jwkest.jwt import JWT
from oidc_provider.lib.claims import ScopeClaims, StandardScopeClaims
from oidc_provider.lib.utils.token import TokenModule

from hkijwt.models import ApiPermission


LOG = logging.getLogger(__name__)


class HelssoTokenModule(TokenModule):
    def create_id_token(self, user, client, nonce='', at_hash='',
                        request=None, scope=[]):
        data = super(HelssoTokenModule, self).create_id_token(
            user, client, nonce, at_hash, request, scope)
        api_perms_for_client = (
            ApiPermission.objects
            .by_identifiers(scope)
            .allowed_for_client(client))
        apis = {api_perm.api for api_perm in api_perms_for_client}
        extended_scope = sorted(
            set(scope) |
            set(sum((list(api.scopes) for api in apis), [])))
        userinfo = get_userinfo(user, extended_scope, client)
        data.update(userinfo)
        allowed_apis = set()
        for api in apis:
            missing_scopes = api.get_missing_scopes(scope)
            if not missing_scopes:
                allowed_apis.add(api)
            else:
                LOG.warning(
                    "API '%s' needs these ungranted scopes: %s",
                    api, missing_scopes)
        data['azp'] = client.client_id
        api_audiences = sorted(api.audience for api in allowed_apis)
        data['aud'] = [client.client_id] + api_audiences
        allowed_perms = sorted(
            api_perm.identifier for api_perm in api_perms_for_client
            if api_perm.api in allowed_apis)
        data['api_perms'] = allowed_perms
        return data

    def client_id_from_id_token(self, id_token):
        payload = JWT().unpack(id_token).payload()
        # See https://stackoverflow.com/questions/32013835
        azp = payload.get('azp', None)  # azp = Authorized Party
        aud = payload.get('aud', None)
        first_aud = aud[0] if isinstance(aud, list) else aud
        return azp if azp else first_aud


def sub_generator(user):
    return str(user.uuid)


class GithubUsernameScopeClaims(ScopeClaims):
    info_github_username = (_("GitHub username"), _("Access to your GitHub username."))

    def scope_github_username(self):
        social_accounts = self.user.socialaccount_set
        github_account = social_accounts.filter(provider='github').first()
        if not github_account:
            return {}
        github_data = github_account.extra_data
        return {
            'github_username': github_data.get('login'),
        }


class ApiTokensScopeClaims(ScopeClaims):
    @classmethod
    def get_scopes_info(cls, scopes=[]):
        api_perms_by_identifier = {
            api_perm.identifier: api_perm
            for api_perm in ApiPermission.objects.filter(identifier__in=scopes)
        }
        api_perms = (api_perms_by_identifier.get(scope) for scope in scopes)
        return [
            {
                'scope': api_perm.identifier,
                'name': api_perm.name,
                'description': api_perm.description,
            }
            for api_perm in api_perms if api_perm
        ]

    def create_response_dic(self):
        result = super(ApiTokensScopeClaims, self).create_response_dic()
        return result
        api_scopes = set(x for x in self.scopes if x.startswith('api-'))
        api_tokens = ApiPermission.get_api_tokens(
            api_scopes, self.client, self.user, self.scopes)
        for (api_identifier, token) in api_tokens.items():
            result['api-' + api_identifier] = token
        return result


class CombinedScopeClaims(ScopeClaims):
    combined_scope_claims = [
        ApiTokensScopeClaims,
        GithubUsernameScopeClaims,
    ]

    @classmethod
    def get_scopes_info(cls, scopes=[]):
        scopes_info_map = {}
        for claim_cls in cls.combined_scope_claims:
            for info in claim_cls.get_scopes_info(scopes):
                scopes_info_map[info['scope']] = info
        return [
            scopes_info_map[scope]
            for scope in scopes
            if scope in scopes_info_map
        ]

    def create_response_dic(self):
        result = super(CombinedScopeClaims, self).create_response_dic()
        token = FakeToken.from_claims(self)
        for claim_cls in self.combined_scope_claims:
            claim = claim_cls(token)
            result.update(claim.create_response_dic())
        return result


class FakeToken(object):
    """
    Object that adapts a token.

    ScopeClaims constructor needs a token, but really uses just its
    user, scope and client attributes.  This adapter makes it possible
    to create a token like object from those three attributes or from a
    claims object (which doesn't store the token) allowing it to be
    passed to a ScopeClaims constructor.
    """
    def __init__(self, user, scope, client):
        self.user = user
        self.scope = scope
        self.client = client

    @classmethod
    def from_claims(cls, claims):
        return cls(claims.user, claims.scopes, claims.client)


def get_userinfo(user, scopes, client=None):
    token = FakeToken(user, scopes, client)
    result = {}
    result.update(StandardScopeClaims(token).create_response_dic())
    result.update(CombinedScopeClaims(token).create_response_dic())
    return result
