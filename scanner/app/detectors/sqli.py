from ..schemas import Finding


SQL_ERROR_HINTS = [
    "sql syntax",
    "sqlite",
    "database error",
    "syntax error",
    "unrecognized token",
    "operationalerror",
]


async def detect(base, difficulty, client, assessment_mode="blackbox"):

    endpoint = "/labs/sqli"

    if difficulty == "expert":

        await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "prepare": "1",
                "raw": "1",
            },
        )

    baseline = await client.get(
        base + endpoint,
        params={
            "level": difficulty,
            "id": "1",
            "raw": "1",
        },
    )

    mutated = await client.get(
        base + endpoint,
        params={
            "level": difficulty,
            "id": "1'",
            "raw": "1",
        },
    )

    mutated_lower = mutated.text.lower()

    error_hit = any(
        hint in mutated_lower
        for hint in SQL_ERROR_HINTS
    )

    status_changed = (
        baseline.status_code
        != mutated.status_code
    )

    size_delta = abs(
        len(baseline.content)
        - len(mutated.content)
    )

    content_changed = (
        baseline.text
        != mutated.text
    )

    confidence = 0.0

    if error_hit:
        confidence += 0.55

    if status_changed:
        confidence += 0.20

    if size_delta >= 10:
        confidence += 0.10

    if content_changed:
        confidence += 0.10

    confidence = min(
        confidence,
        0.95,
    )

    if confidence < 0.40:
        return []

    evidence_parts = []

    if error_hit:
        evidence_parts.append(
            "database error signature observed"
        )

    if status_changed:
        evidence_parts.append(
            f"HTTP status changed "
            f"{baseline.status_code}->{mutated.status_code}"
        )

    if content_changed:
        evidence_parts.append(
            "response content changed reproducibly"
        )

    evidence_parts.append(
        f"response size delta={size_delta} bytes"
    )

    return [
        Finding(
            vulnerability="Potential SQL Injection",
            endpoint=endpoint,
            parameter="id",
            severity="High",
            confidence=confidence,
            cwe="CWE-89",
            evidence="; ".join(evidence_parts),
            detection_method=(
                "Safe SQL syntax mutation and "
                "differential response analysis"
            ),
            exploitation_performed=False,
            recommendation=(
                "Use parameterized queries or prepared "
                "statements and avoid SQL string concatenation."
            ),
            difficulty=difficulty,
            assessment_mode=assessment_mode,
        )
    ]
