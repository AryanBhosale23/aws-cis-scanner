from scanner.runner import check_order


def test_checks_are_ordered_by_their_number_not_alphabetically():
    ids = ["VPC-15", "IAM-01", "CT-11", "S3-07", "IAM-20", "KMS-19"]
    assert sorted(ids, key=check_order) == [
        "IAM-01",
        "S3-07",
        "CT-11",
        "VPC-15",
        "KMS-19",
        "IAM-20",
    ]