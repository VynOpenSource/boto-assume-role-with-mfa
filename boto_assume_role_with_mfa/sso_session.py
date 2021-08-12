"""
Implementation files for assuming roles using SSO session
"""
from aws_sso_lib import list_available_roles, get_boto3_session
from boto3 import Session

from boto_assume_role_with_mfa import SessionProvider
from boto_assume_role_with_mfa.arn import ARN


class SSOSessionProvider(SessionProvider):
    """
    SessionProvider which uses an SSO session
    """

    @property
    def temporary_credentials(self) -> dict:
        raise NotImplementedError("SSO session uses token, not credentials")

    def __init__(self, *, start_url: str, sso_region: str):
        self._start_url = start_url
        self._sso_region = sso_region

    def assume_role_session(
        self,
        *,
        role_arn: str,
        region_name: str,
        session_name: str,  # pylint: disable=unused-argument
    ) -> Session:
        """
        Assume a role using the SSO session and return the credentials

        :param role_arn: the role to assume
        :param region_name: the region you will use
        :param session_name: a session name (unused)

        :return: the credentials of the new session
        """
        arn = ARN(role_arn)
        return get_boto3_session(
            start_url=self._start_url,
            sso_region=self._sso_region,
            account_id=arn.account,
            role_name=arn.resource,
            region=region_name,
            login=True,
        )

    def assume_role_credentials(
            self, *, role_arn: str, region_name: str, session_name: str
    ) -> dict:
        """
        Assume a role using the SSO session and return a new session

        :param role_arn: the role to assume
        :param region_name: the region you will use
        :param session_name: a session name

        :return: the new session
        """
        session = self.assume_role_session(
            role_arn=role_arn, region_name=region_name, session_name=session_name
        )
        credentials = session.get_credentials()
        temp_credentials = {
            "AccessKeyId": credentials.access_key,
            "SecretAccessKey": credentials.secret_key,
            "SessionToken": credentials.token,
        }
        return temp_credentials

    def _get_any_role(self) -> ARN:
        for role in list_available_roles(
            sso_region=self._sso_region,
            start_url=self._start_url,
            login=True,
        ):
            return ARN(f"arn:aws:iam::{role[0]}:role/{role[2]}")
        raise Exception("No accessible roles found")

    def get_user(self) -> str:
        """
        The best solution found so far is to assume first available role and call
        `get_caller_identity()`
        :return: The SSO user name
        """
        role = self._get_any_role()
        session = self.assume_role_session(
            role_arn=role.full_arn, region_name="eu-west-1", session_name="test"
        )
        sts = session.client("sts")
        user_identity = sts.get_caller_identity()
        return user_identity["UserId"].split(":", 2)[1]
