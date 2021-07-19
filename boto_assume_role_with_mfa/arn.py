"""
AWS ARN parser
"""
from typing import List, Tuple, Optional


class ARN:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    """
    AWS ARN parser
    """

    def __init__(self, arn: str):
        self.full_arn = arn
        elements = arn.split(":")
        self.arn = elements[0]
        self.partition = elements[1]
        self.service = elements[2]
        self.region = elements[3]
        self.account = elements[4]
        self.resource_type, self.resource = self._get_resource(elements)

    @staticmethod
    def _get_resource(elements: List[str]) -> Tuple[Optional[str], str]:
        if len(elements) == 7:
            return elements[5], elements[6]
        if "/" not in elements[5]:
            return None, elements[5]
        resource = elements[5].split("/", 1)
        return resource[0], resource[1]
