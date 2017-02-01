import logging
from collections import defaultdict

from django.utils.translation import ugettext_lazy as _

from hkijwt.models import ApiScope
from jwkest.jwt import JWT
from oidc_provider.lib.claims import ScopeClaims, StandardScopeClaims
from oidc_provider.lib.utils.token import TokenModule


LOG = logging.getLogger(__name__)


class HelssoTokenModule(TokenModule):
    def create_id_token(self, user, client, nonce='', at_hash='',
                        request=None, scope=[]):
        """
        :type user: users.models.User
        :type client: oidc_provider.models.Client
        :type nonce: str
        :type at_hast: str
        :type request: django.http.HttpRequest|None
        :type scope: list[str]
        """
        data = super(HelssoTokenModule, self).create_id_token(
            user, client, nonce, at_hash, request, scope)

        (api_scope, api_aud, api_claims) = self._get_api_data(client, scope)

        extended_scope = set(scope) | set(api_scope)
        userinfo = get_userinfo(user, extended_scope, client)
        data.update(userinfo)
        data.update(api_claims)
        data['aud'] = [client.client_id] + api_aud
        data['azp'] = client.client_id
        return data

    def _get_api_data(self, client, scope):
        api_scopes = (
            ApiScope.objects.by_identifiers(scope)
            .allowed_for_client(client))
        apis = {api_scope.api for api_scope in api_scopes}

        # Collect scopes required by APIs
        required_scopes = set(sum(
            (list(api.required_scopes) for api in apis), []))

        # Collect audiences
        api_audiences = sorted(api.identifier for api in apis)

        # Collect API scope claims
        claims = defaultdict(list)
        for api_scope in api_scopes:
            field = api_scope.api.domain.identifier
            claims[field].append(api_scope.relative_identifier)

        return (required_scopes, api_audiences, claims)

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
    info_github_username = (
        _("GitHub username"), _("Access to your GitHub username."))

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
        scopes_by_identifier = {
            api_scope.identifier: api_scope
            for api_scope in ApiScope.objects.by_identifiers(scopes)
        }
        api_scopes = (scopes_by_identifier.get(scope) for scope in scopes)
        return [
            {
                'scope': api_scope.identifier,
                'name': api_scope.name,
                'description': api_scope.description,
            }
            for api_scope in api_scopes if api_scope
        ]


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
