import unittest

from boto_assume_role_with_mfa.arn import ARN


class ARNTest(unittest.TestCase):

    def test_admin_role_arn(self):
        role_arn = ARN("arn:aws:iam::123456789012:role/administrator")
        self.assertEqual(role_arn.account, "123456789012")
        self.assertEqual(role_arn.resource_type, "role")
        self.assertEqual(role_arn.resource, "administrator")

    def test_role_arn_with_slash(self):
        role_arn = ARN("arn:aws:iam::123456789012:role/common-roles/developer")
        self.assertEqual(role_arn.account, "123456789012")
        self.assertEqual(role_arn.resource_type, "role")
        self.assertEqual(role_arn.resource, "common-roles/developer")

    def test_role_arn_with_colon(self):
        role_arn = ARN("arn:aws:iam::123456789012:role:common-roles/developer")
        self.assertEqual(role_arn.account, "123456789012")
        self.assertEqual(role_arn.resource_type, "role")
        self.assertEqual(role_arn.resource, "common-roles/developer")
