"""
Implementation files for assuming roles using MFA session caching
"""
import abc
import datetime
import logging
from typing import Optional, Tuple

import pytz
from boto3 import Session
from botocore import credentials
from botocore.client import BaseClient
from botocore.credentials import JSONFileCache
from dateutil.parser import parse


class SessionCache:
    """ This is an internal API not intended for public use """

    logger = logging.getLogger(__name__)

    def __init__(self, *, cache: JSONFileCache):
        self._cache = cache

    def get_session_token(self, *, key: str) -> Optional[dict]:
        """
        :param key: the key to use to index the cache
        :return: the session token from the cache or none if expired or missing
        """
        session_data = self._get_cached_session(key=key)

        if session_data and self._is_expired(session_data=session_data):
            self.logger.info("No session cache (or existing has expired)")
            return None

        self.logger.info("Found unexpired session data in cache: %s", key)

        return session_data

    def _is_expired(self, *, session_data: dict) -> bool:
        expiration = session_data["Credentials"]["Expiration"]
        if isinstance(expiration, str):
            expiration = parse(expiration)

        now = datetime.datetime.now(tz=pytz.utc)

        expired = expiration < now
        self.logger.info(
            "Session expires at %s, currently %s, expired:%s", expiration, now, expired
        )
        return expired

    def _get_cached_session(self, *, key: str) -> Optional[dict]:
        try:
            return self._cache[key]
        except KeyError:
            self.logger.info("No session found in cache for %s", key)
        return None

    def cache_session(self, *, key: str, data: dict):
        """
        :param key: the index into the cache
        :param data: the session data to cache
        :return: None
        """
        self._cache[key] = data


def _get_account_and_user(*, sts_client: BaseClient) -> Tuple[str, str]:
    """ This is an internal API not intended for public use """
    identity = sts_client.get_caller_identity()
    arn = identity["Arn"]
    return identity["Account"], arn.split("/")[-1]


class CachedMfaSessionFactory:
    """ This is an internal API not intended for public use """

    # pylint: disable=too-few-public-methods
    SESSION_KEY = "temporary_session"
    MFA_SESSION_DURATION = datetime.timedelta(hours=12)

    logger = logging.getLogger(__name__)

    def __init__(self, *, sts_client: BaseClient, session_cache: SessionCache):
        self._sts_client = sts_client
        self._session_cache = session_cache

    def get_session_token(self, *, mfa_token: Optional[str] = None) -> dict:
        """
        It will use STS to get a new session token, or use a previously cached token if one is
        available.

        :param mfa_token: if you do not specify the mfa token, this method will prompt for it
        :return: temporary credentials for a new session as created by the sts GetSessionToken api
        """
        session_data = self._session_cache.get_session_token(key=self.SESSION_KEY)
        if session_data:
            return session_data
        return self._create_session(mfa_token=mfa_token)

    def _create_session(self, *, mfa_token: Optional[str] = None) -> dict:
        if not mfa_token:
            self.logger.info("No session for:%s, prompt for MFA", self.SESSION_KEY)
            mfa_token = input("MFA code:")

        account, user = _get_account_and_user(sts_client=self._sts_client)
        session_data = self._sts_client.get_session_token(
            DurationSeconds=CachedMfaSessionFactory.MFA_SESSION_DURATION.seconds,
            SerialNumber=f"arn:aws:iam::{account}:mfa/{user}",
            TokenCode=mfa_token,
        )
        self._session_cache.cache_session(key=self.SESSION_KEY, data=session_data)
        return session_data


class SessionProvider:
    """
    Interface for session providers
    """

    @property
    @abc.abstractmethod
    def temporary_credentials(self) -> dict:
        """
        :return: the credentials in use by the base session
        """
        raise NotImplementedError

    @abc.abstractmethod
    def assume_role_credentials(
        self, *, role_arn: str, region_name: str, session_name: str
    ) -> dict:
        """
        Assume a role using the underlying session and return the credentials

        :param role_arn: the role to assume
        :param region_name: the region you will use
        :param session_name: a session name

        :return: the credentials of the new session
        """
        raise NotImplementedError

    @abc.abstractmethod
    def assume_role_session(
        self, *, role_arn: str, region_name: str, session_name: str
    ) -> Session:
        """
        Assume a role using the underlying session and return a new session

        :param role_arn: the role to assume
        :param region_name: the region you will use
        :param session_name: a session name

        :return: the new session
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_user(self) -> str:
        """
        :return: the user name of the user who owns the base session
        """
        raise NotImplementedError


class MFASessionProvider(SessionProvider):
    """
    Uses a base session to provide assume role credentials with cached MFA
    """

    logger = logging.getLogger(__name__)

    ASSUME_ROLE_SESSION_DURATION = datetime.timedelta(hours=1)

    def __init__(self, *, session_data: dict):
        self._session_data = session_data

    @property
    def temporary_credentials(self) -> dict:
        """
        :return: the credentials in use by the base session
        """
        return self._session_data["Credentials"]

    def _create_temporary_session(self, *, region_name: str) -> Session:
        return self._get_session_from(
            aws_access_key_id=self._session_data["Credentials"]["AccessKeyId"],
            aws_secret_access_key=self._session_data["Credentials"]["SecretAccessKey"],
            aws_session_token=self._session_data["Credentials"]["SessionToken"],
            region_name=region_name,
        )

    def assume_role_credentials(
        self, *, role_arn: str, region_name: str, session_name: str
    ) -> dict:
        """
        Assume a role using the underlying session and return the credentials

        :param role_arn: the role to assume
        :param region_name: the region you will use
        :param session_name: a session name

        :return: the credentials of the new session
        """
        temp_sts_client = self._create_temporary_session(
            region_name=region_name
        ).client("sts")

        session_data = temp_sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=self.ASSUME_ROLE_SESSION_DURATION.seconds,
        )
        return session_data["Credentials"]

    def assume_role_session(
        self, *, role_arn: str, region_name: str, session_name: str
    ) -> Session:
        """
        Assume a role using the underlying session and return a new session

        :param role_arn: the role to assume
        :param region_name: the region you will use
        :param session_name: a session name

        :return: the new session
        """
        role_credentials = self.assume_role_credentials(
            role_arn=role_arn, region_name=region_name, session_name=session_name
        )

        return self._get_session_from(
            aws_access_key_id=role_credentials["AccessKeyId"],
            aws_secret_access_key=role_credentials["SecretAccessKey"],
            aws_session_token=role_credentials["SessionToken"],
            region_name=region_name,
        )

    def get_user(self) -> str:
        """
        :return: the user name of the user who owns the base session
        """
        temp_sts_client = self._create_temporary_session(
            region_name="eu-west-1"
        ).client("sts")
        return _get_account_and_user(sts_client=temp_sts_client)[1]

    @staticmethod
    def _get_session_from(
        *,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: str = None,
        region_name: str = None,
    ) -> Session:
        session_properties = {
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
        }
        if aws_session_token:
            session_properties["aws_session_token"] = aws_session_token
        if region_name:
            session_properties["region_name"] = region_name

        return Session(**session_properties)

    @staticmethod
    def create(*, profile_name: str):
        """
        Create a new session provider with MFA authentication, that you can use to create temporary
        assume role sessions for roles that are protected by policies requiring MFA

        :param profile_name: the profile to use to create the base session

        :return: the SessionProvider
        """
        session = Session(profile_name=profile_name)
        session_cache = SessionCache(cache=credentials.JSONFileCache())
        session_factory = CachedMfaSessionFactory(
            sts_client=session.client("sts"), session_cache=session_cache
        )

        return MFASessionProvider(session_data=session_factory.get_session_token())
