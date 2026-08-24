from ..schemas import Finding


MARKER = "VULNLAB_LFI_MARKER"


async def detect(base, difficulty, client, assessment_mode="blackbox"):

    endpoint = "/labs/lfi"

    if difficulty == "expert":

        await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "prepare": "1",
                "raw": "1",
            },
        )

    response = await client.get(
        base + endpoint,
        params={
            "level": difficulty,
            "name": "lfi-marker.txt",
            "raw": "1",
        },
    )

    if MARKER not in response.text:
        return []

    return [
        Finding(
            vulnerability="Local File Inclusion Behavior",
            endpoint=endpoint,
            parameter="name",
            severity="High",
            confidence=0.94,
            cwe="CWE-98",
            evidence=(
                f"Controlled laboratory marker {MARKER} "
                "was returned from the requested file."
            ),
            detection_method=(
                "Controlled marker-file retrieval"
            ),
            exploitation_performed=False,
            recommendation=(
                "Avoid directly constructing file paths "
                "from user input. Use an explicit file allowlist."
            ),
            difficulty=difficulty,
            assessment_mode=assessment_mode,
        )
    ]
