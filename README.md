In order to secure the use of particular roles within AWS you may implement policies that require
MFA on the session that is attempting to assume the protected role. To make this less annoying we
would also like to cache the MFA credentials for some time, and across which ever roles are being
used.

The approach we take here is to use the boto `JSONFileCache`. We start a base session with your user
profile, then we use the base session to request a temporary session with MFA protection. In turn
this temporary session can now be used to assume roles, possible across accounts, even if assuming
those roles requires MFA by policy.

### Example Usage:

```
from boto_assume_role_with_mfa import SessionProvider

session_provider = SessionProvider.create(profile_name='example')
session = session_provider.assume_role_session(
    role_arn='arn:aws:iam::123456789012:role/demo',
    region_name='eu-west-1',
    session_name='testAR'
)
```

### Development

You can run the tests using [Tox](https://tox.readthedocs.io/en/latest/) you will also
need [Poetry](https://python-poetry.org). You can test the github actions
using [Act](https://github.com/nektos/act). You can make multiple python versions available to tox
by running `pyenv local 3.6.13 3.7.10 3.8.7 3.9.1` or similar.
