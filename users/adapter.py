from django.contrib.auth import get_user_model

from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.utils import email_address_exists
from allauth.account.utils import user_email

from .models import LoginMethod


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def populate_user(self, request, sociallogin, data):
        User = get_user_model()
        if sociallogin.account.provider == 'adfs':
            try:
                user = User.objects.get(uuid=data.get('uuid'))
                sociallogin.user = user
            except User.DoesNotExist:
                pass

        user = super().populate_user(request, sociallogin, data)
        if sociallogin.account.provider == 'adfs':
            user.primary_sid = data.get('primary_sid')
            user.uuid = data.get('uuid')
            user.department_name = data.get('department_name')

        return user

    def clean_username(self, username, shallow=False):
        return username.lower()

    def is_auto_signup_allowed(self, request, sociallogin):
        email = user_email(sociallogin.user)
        assert email
        # Always trust ADFS logins
        if sociallogin.account.provider == 'adfs':
            return True
        if email_address_exists(email):
            return False
        return True

    def is_open_for_signup(self, request, sociallogin):
        email = user_email(sociallogin.user)
        # If we have a user with that email already, we don't allow
        # a signup through a new provider. Revisit this in the future.
        if email_address_exists(email):
            User = get_user_model()
            try:
                user = User.objects.get(email__iexact=email)
                social_set = user.socialaccount_set.all()
                # If the account doesn't have any social logins yet,
                # allow the signup.
                if not social_set:
                    return True
                providers = [a.provider for a in social_set]
                request.other_logins = LoginMethod.objects.filter(provider_id__in=providers)
            except User.DoesNotExist:
                request.other_logins = []
            return False
        else:
            return True
