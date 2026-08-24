WEIGHTS = {
    "Critical": 30,
    "High": 18,
    "Medium": 8,
    "Low": 3,
    "Info": 0,
}


def security_score(findings):

    penalty = 0

    for finding in findings:

        if hasattr(
            finding,
            "severity",
        ):
            severity = finding.severity

        else:
            severity = finding.get(
                "severity",
                "Info",
            )

        penalty += WEIGHTS.get(
            severity,
            0,
        )

    return max(
        0,
        100 - penalty,
    )
