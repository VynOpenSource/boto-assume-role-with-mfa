import datetime
import unittest
from unittest.mock import Mock

import pytz
from botocore.client import BaseClient
from botocore.credentials import JSONFileCache

from boto_assume_role_with_mfa.mfa_session import SessionCache, CachedMfaSessionFactory


class InMemoryCache(JSONFileCache):

    def __init__(self):
        super().__init__()
        self._cache = {}

    def __contains__(self, cache_key):
        return self._cache.__contains__(cache_key)

    def __getitem__(self, cache_key):
        return self._cache.__getitem__(cache_key)

    def __setitem__(self, cache_key, value):
        self._cache[cache_key] = value


SESSION_DATA = {
    "Credentials": {
        "AccessKeyId": "temporary_access_key_id",
        "SecretAccessKey": "temporary_secret_access_key",
        "SessionToken": "token",
        "Expiration": "2020-10-01T17:08:49UTC"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "temporary_access_key_id:fred",
        "Arn": "arn:aws:sts::496141846484:assumed-role/admin/fred"
    },
    "ResponseMetadata": {
        "RequestId": "4f396cb1-3c68-11ea-94b0-71e1440a90e9",
        "HTTPStatusCode": 200,
        "HTTPHeaders": {
            "x-amzn-requestid": "4f396cb1-3c68-11ea-94b0-71e1440a90e9",
            "content-type": "text/xml", "content-length": "1047",
            "date": "Mon, 05 Oct 2020 16:08:49 GMT"
        },
        "RetryAttempts": 0
    }
}


class SessionCacheTest(unittest.TestCase):

    def test_cache_manager(self):
        session_cache = SessionCache(cache=InMemoryCache())

        self.assertIsNone(session_cache.get_session_token(key="key"))

    def test_cache_manager_warm(self):
        cache = InMemoryCache()
        session_data = SESSION_DATA

        now = datetime.datetime.now(tz=pytz.utc)
        one_hour_in_future = (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S%Z")

        session_data['Credentials']["Expiration"] = one_hour_in_future
        cache.__setitem__("key", session_data)
        session_cache = SessionCache(cache=cache)

        self.assertIsNotNone(session_cache.get_session_token(key="key"))


def get_current_session_data() -> dict:
    session_data = SESSION_DATA

    now = datetime.datetime.now(tz=pytz.utc)
    one_hour_in_future = (now + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S%Z")

    session_data['Credentials']["Expiration"] = one_hour_in_future

    return session_data


class CachedMfaSessionFactoryTest(unittest.TestCase):

    def test_temporary_credentials_in_cache(self):
        cache = InMemoryCache()

        cache.__setitem__(CachedMfaSessionFactory.SESSION_KEY, get_current_session_data())

        cached_mfa_session_factory = CachedMfaSessionFactory(
            sts_client=Mock(BaseClient),
            session_cache=SessionCache(cache=cache))
        temporary_session_data = cached_mfa_session_factory.get_session_token()
        credentials = temporary_session_data['Credentials']
        self.assertEqual(credentials.get('AccessKeyId'), "temporary_access_key_id")
        self.assertEqual(credentials.get('SecretAccessKey'), "temporary_secret_access_key")

    def test_temporary_credentials_from_session(self):
        sts_client = Mock(BaseClient)
        sts_client.get_caller_identity = Mock(
            return_value={'Arn': 'arn', 'Account': '123456789012'}
        )
        sts_client.get_session_token = Mock(return_value=get_current_session_data())

        cache = InMemoryCache()

        cached_mfa_session_factory = CachedMfaSessionFactory(
            sts_client=sts_client,
            session_cache=SessionCache(cache=cache))

        temporary_session_data = cached_mfa_session_factory.get_session_token(
            mfa_token="token"
        )['Credentials']
        self.assertEqual(temporary_session_data.get('AccessKeyId'), "temporary_access_key_id")
        self.assertEqual(
            temporary_session_data.get('SecretAccessKey'),
            "temporary_secret_access_key"
        )

        self.assertIsNotNone(cached_mfa_session_factory.get_session_token())
