import hashlib
import logging
import uuid

from django.conf import settings
from djangosaml2.backends import Saml2Backend


logger = logging.getLogger(__name__)


class HelsinkiBackend(Saml2Backend):
    def _clean_attributes(self, session_info):
        attrs = session_info['ava']
        for attr in ('organizationName', 'emailAddress',
                     'windowsAccountName'):
            if attr not in attrs:
                continue
            attrs[attr][0] = attrs[attr][0].lower()
        if 'displayName' in attrs:
            names = attrs['displayName'][0].split(' ')
            attrs['lastName'] = [names[0]]
            attrs['firstName'] = [' '.join(names[1:])]

        if 'primarySID' in attrs:
            domain_uuid = uuid.UUID(settings.ADFS_DOMAIN_UUID)
            user_uuid = uuid.uuid5(domain_uuid, attrs['primarySID'][0]).hex
            attrs['uuid'] = [user_uuid]

    def authenticate(self, session_info=None, attribute_mapping=None,
                     create_unknown_user=True):
        if session_info:
            self._clean_attributes(session_info)
        return super(HelsinkiBackend, self).authenticate(session_info, attribute_mapping,
                                                         create_unknown_user)
