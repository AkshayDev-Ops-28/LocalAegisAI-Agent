from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

REQUIRED_TAGS = ["Project", "Owner"]


class CheckS3MandatoryTags(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has mandatory Project and Owner tags"
        id = "CKV_LOCAL_1"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources
        )

    def scan_resource_conf(self, conf: dict) -> CheckResult:
        tags = conf.get("tags", [{}])
        if isinstance(tags, list):
            tags = tags[0] if tags else {}
        if not isinstance(tags, dict):
            return CheckResult.FAILED
        for required in REQUIRED_TAGS:
            if required not in tags:
                return CheckResult.FAILED
        return CheckResult.PASSED


scanner = CheckS3MandatoryTags()