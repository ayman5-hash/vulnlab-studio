from ..schemas import Finding


MARKER = "VULNLAB_RFI_MARKER"

RESOURCE_URL = (
    "http://127.0.0.1:9000/marker.txt"
)


async def detect(base, difficulty, client, assessment_mode="blackbox"):

    endpoint = "/labs/rfi"

    if difficulty == "expert":

        await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "prepare": "1",
                "url": RESOURCE_URL,
                "raw": "1",
            },
        )

    response = await client.get(
        base + endpoint,
        params={
            "level": difficulty,
            "url": RESOURCE_URL,
            "raw": "1",
        },
    )

    if MARKER not in response.text:
        return []

    return [
        Finding(
            vulnerability=(
                "Controlled Remote Resource "
                "Inclusion Behavior"
            ),
            endpoint=endpoint,
            parameter="url",
            severity="High",
            confidence=0.96,
            cwe="CWE-98",
            evidence=(
                f"Controlled loopback resource marker "
                f"{MARKER} was returned. "
                "No external host was contacted."
            ),
            detection_method=(
                "Loopback-only marker resource validation"
            ),
            exploitation_performed=False,
            recommendation=(
                "Do not retrieve server-side resources "
                "from user-controlled URLs. Apply strict "
                "allowlists where remote retrieval is required."
            ),
            difficulty=difficulty,
            assessment_mode=assessment_mode,
        )
    ]
