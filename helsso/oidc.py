from django.utils.translation import ugettext_lazy as _
from oidc_provider.lib.claims import ScopeClaims, StandardScopeClaims

from hkijwt.models import ApiPermission


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
        fake_token = _ClaimsTokenAdapter(self)
        for claim_cls in self.combined_scope_claims:
            claim = claim_cls(fake_token)
            result.update(claim.create_response_dic())
        return result


class _ClaimsTokenAdapter(object):
    """
    Object that adapts a token, created from a claims object.

    ScopeClaims constructor needs a token, but does not store it.  This
    adapter makes it possible to create a token like object from a
    claims object, allowing it to be passed for another ScopeClaims
    constructor.
    """
    def __init__(self, claims):
        self.user = claims.user
        self.scope = claims.scopes
        self.client = claims.client


class FakeToken(object):
    pass


def get_userinfo(user, scopes, client=None):
    token = FakeToken()
    token.user = user
    token.scope = scopes
    token.client = client
    result = {}
    result.update(StandardScopeClaims(token).create_response_dic())
    result.update(CombinedScopeClaims(token).create_response_dic())
    return result
