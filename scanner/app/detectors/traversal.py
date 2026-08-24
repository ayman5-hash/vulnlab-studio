from ..schemas import Finding


MARKER = "VULNLAB_TRAVERSAL_MARKER"


PAYLOADS = {
    "easy": (
        "lab_files/traversal-marker.txt"
    ),

    "medium": (
        "public_files/....//lab_files/"
        "traversal-marker.txt"
    ),

    "hard": (
        "../lab_files/traversal-marker.txt"
    ),

    "expert": (
        "../lab_files/traversal-marker.txt"
    ),
}


async def detect(base, difficulty, client, assessment_mode="blackbox"):

    endpoint = "/labs/traversal"

    if difficulty == "expert":

        await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "prepare": "1",
                "raw": "1",
            },
        )

    payload = PAYLOADS.get(
        difficulty,
        PAYLOADS["easy"],
    )

    response = await client.get(
        base + endpoint,
        params={
            "level": difficulty,
            "path": payload,
            "raw": "1",
        },
    )

    if MARKER not in response.text:
        return []

    return [
        Finding(
            vulnerability="Path Traversal",
            endpoint=endpoint,
            parameter="path",
            severity="High",
            confidence=0.95,
            cwe="CWE-22",
            evidence=(
                f"Controlled traversal marker {MARKER} "
                f"was returned using laboratory path "
                f"variant for level {difficulty}."
            ),
            detection_method=(
                "Controlled marker path and "
                "path-normalization analysis"
            ),
            exploitation_performed=False,
            recommendation=(
                "Resolve paths against an approved base "
                "directory and reject paths escaping that root."
            ),
            difficulty=difficulty,
            assessment_mode=assessment_mode,
        )
    ]
