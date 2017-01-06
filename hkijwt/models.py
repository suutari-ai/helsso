import logging
import re
from collections import defaultdict

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from multiselectfield import MultiSelectField
from oidc_provider.models import Client
from parler.fields import TranslatedField
from parler.models import TranslatableModel, TranslatedFieldsModel

from .apikey import generate_api_token
from .mixins import AutoFilledIdentifier, ImmutableFields


LOG = logging.getLogger(__name__)


api_identifier_validator = RegexValidator(
    '^[a-z0-9]+$',
    message=_("May contain only lower case letters and digits."))

api_permission_identifier_validator = RegexValidator(
    '^api-[a-z0-9]+(-[a-z0-9]+)*$',
    message=_("Must start with \"api-\" and may contain "
              "only lower case letters, digits and dashes."))

SCOPE_CHOICES = [
    ('email', _("E-mail")),
    ('profile', _("Profile")),
    ('address', _("Address")),
    ('github_username', _("GitHub username")),
]


class Api(AutoFilledIdentifier, ImmutableFields, models.Model):
    immutable_fields = ['identifier']

    audience = models.CharField(
        max_length=200,
        verbose_name=_("audience"))
    identifier = models.CharField(
        max_length=50, unique=True,
        validators=[api_identifier_validator],
        verbose_name=_("identifier"),
        help_text=_("Leave empty to autofill from audience."))
    scopes = MultiSelectField(
        choices=SCOPE_CHOICES, max_length=200,
        default=['email', 'profile'],
        verbose_name=_("scopes"),
        help_text=_("Select scopes to include to the API token."))

    class Meta:
        verbose_name = _("API")
        verbose_name_plural = _("APIs")

    def scopes_string(self):
        return ' '.join(self.scopes)
    scopes_string.short_description = _("scopes")

    def get_granted_scopes(self, all_granted_scopes):#TODO: Remove ################################
        wanted = set(self.scopes)
        granted = set(all_granted_scopes)
        result = wanted.intersection(granted)
        if result != wanted:
            LOG.warning(
                "API '%s' needs these ungranted scopes: %s",
                self, wanted - result)
        return result

    def check_granted_scopes(self, granted_scopes):
        missing = set(self.scopes) - set(granted_scopes)
        if missing:
            LOG.warning(
                "API '%s' needs these ungranted scopes: %s",
                self, missing)
        return missing

    def _generate_identifier(self):
        return re.sub('[^a-z-]', '', slugify(
            self.audience
            .split('//', 1)[-1]  # remove possible schema, e.g. "https://"
            .split('/', 1)[0].split('.', 1)[0]))  # take only hostname


class ApiPermission(AutoFilledIdentifier, ImmutableFields, TranslatableModel):
    immutable_fields = ['api', 'specifier', 'identifier']

    api = models.ForeignKey(
        Api, related_name='permissions',
        verbose_name=_("API"),
        help_text=_("The API that this permission is for."))
    specifier = models.CharField(
        max_length=30, blank=True,
        verbose_name=_("specifier"),
        help_text=_(
            "If there is a need for multiple permissions per API, "
            "this can specify what kind of permission this is about, "
            "e.g. \"read\" or \"write\".  For general API access "
            "permisison just leave this empty."))
    identifier = models.CharField(
        max_length=100, unique=True, editable=False,
        validators=[api_permission_identifier_validator],
        verbose_name=_("identifier"),
        help_text=_(
            "The permission identifier as known by the "
            "API provider application.  Filled automatically "
            "from API identifier and permission specifier."))
    name = TranslatedField()
    description = TranslatedField()
    allowed_apps = models.ManyToManyField(
        Client, related_name='granted_api_permissions',
        verbose_name=_("allowed applications"),
        help_text=_("Select client applications which are allowed "
                    "to get access to this API permission."))

    class Meta:
        verbose_name = _("API permission")
        verbose_name_plural = _("API permissions")

    @classmethod
    def get_api_tokens(cls, permissions, client, user, granted_scopes):
        allowed_perms = cls.objects.filter(
            identifier__in=permissions, allowed_apps=client)
        perms_by_api = defaultdict(set)
        for perm in allowed_perms:
            perms_by_api[perm.api].add(perm.identifier)
        return {
            api.identifier: generate_api_token(
                user, api.audience, perm_identifiers,
                api.get_granted_scopes(granted_scopes))
            for (api, perm_identifiers) in perms_by_api.items()
        }

    @classmethod
    def get_api_data(cls, permissions, client, user, granted_scopes):
        allowed_perms = cls.objects.filter(
            identifier__in=permissions, allowed_apps=client)
        apis = set(perm.api for perm in allowed_perms)
        for api in apis:
            api.check_granted_scopes(granted_scopes)
        return {
            'aud': sorted(api.audience for api in apis),
            'perms': [perm.identifier for perm in allowed_perms],
        }

    def _generate_identifier(self):
        return 'api-{api_identifier}{suffix}'.format(
            api_identifier=self.api.identifier,
            suffix=('-' + slugify(self.specifier) if self.specifier else '')
        )


class ApiPermissionTranslation(TranslatedFieldsModel):
    master = models.ForeignKey(
        ApiPermission, related_name='translations', null=True,
        verbose_name=_("API permission"))
    name = models.CharField(
        max_length=200, verbose_name=_("name"))
    description = models.CharField(
        max_length=1000, verbose_name=_("description"))

    class Meta:
        unique_together = ('language_code', 'master')
        verbose_name = _("API permission translation")
        verbose_name_plural = _("API permission translations")

    def __str__(self):
        lang = super(ApiPermissionTranslation, self).__str__()
        return "{}/{}".format(self.master, lang)


class AppToAppPermission(models.Model):
    requester = models.ForeignKey(settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                                  db_index=True, related_name='+')
    target = models.ForeignKey(settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                               db_index=True, related_name='+')

    def __str__(self):
        return "%s -> %s" % (self.requester, self.target)
