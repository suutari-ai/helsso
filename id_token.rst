ID Token
========

ID Token should look like this::
  {
      "iss": "https://oma.hel.fi",
      "auth_time": 1483885641,
      "iat": 1483885643,
      "exp": 1483886243,
      "aud": [
          "332114",
          "https://api.hel.fi/auth/kerrokantasi",
          "https://api.hel.fi/auth/respa"
      ],
      "azp": "332114",
      "at_hash": "aU0XRQdbGq6IEth0z5dppg",
      "nonce": "kze88m"
      "https://api.hel.fi/auth": [
          "kerrokantasi",
          "respa.readonly",
      ],
      "sub": "33e0b08a-b7e3-11e6-b1d7-f0761c0512c2",
      "nickname": "u-gpqlbcvx4mi6nmox6b3bybisyi",
      "given_name": "Tuomas",
      "family_name": "Suutari",
      "github_username": "suutari-ai",
      "email": "tuomas.suutari@gmail.com",
  }


The API scopes are similar to `Google's API scopes
<https://developers.google.com/identity/protocols/googlescopes`_ and
look like this:

=======================================  =================================================
Scope                                    Description
=======================================  =================================================
https://api.hel.fi/auth/kerrokantasi     View and manage your data in Kerrokantasi service
https://api.hel.fi/auth/respa            View and manage your reservations in Varaamo
https://api.hel.fi/auth/respa.readonly   View your reservations in Varaamo
=======================================  ========================================

Authorization for the scopes is requested in OIDC scope parameter, e.g.
``scope="openid https://api.hel.fi/auth/kerrokantasi"``.  Each API scope
might depend on additional OIDC scopes (e.g. ``profile``, ``email``, or
``github_username``) and those will be added automatically so that:

  * If user consent is requested, the automatically included scopes are
    also listed.
  * Automatically added scopes are also included in the ID Token.
