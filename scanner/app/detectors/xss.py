from ..schemas import Finding


MARKER = "VULNLAB_XSS_7f21"


async def detect(base, difficulty, client, assessment_mode="blackbox"):

    endpoint = "/labs/xss"

    # --------------------------------------------------------
    # HARD - stored behavior
    # --------------------------------------------------------

    if difficulty == "hard":

        await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "store": "1",
                "q": MARKER,
                "raw": "1",
            },
        )

        response = await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "raw": "1",
            },
        )

    # --------------------------------------------------------
    # EXPERT - stateful context
    # --------------------------------------------------------

    elif difficulty == "expert":

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
                "q": MARKER,
                "raw": "1",
            },
        )

    # --------------------------------------------------------
    # EASY / MEDIUM
    # --------------------------------------------------------

    else:

        response = await client.get(
            base + endpoint,
            params={
                "level": difficulty,
                "q": MARKER,
                "raw": "1",
            },
        )

    if MARKER not in response.text:
        return []

    text_lower = response.text.lower()

    context = "html-response"
    confidence = 0.70

    if difficulty == "medium":
        confidence = 0.72

    if difficulty == "hard":
        context = "stored-html"
        confidence = 0.82

    if difficulty == "expert":
        if "const labvalue" in text_lower:
            context = "javascript-string"
            confidence = 0.86

    return [
        Finding(
            vulnerability="Potential Cross-Site Scripting",
            endpoint=endpoint,
            parameter="q",
            severity="Medium",
            confidence=confidence,
            cwe="CWE-79",
            evidence=(
                f"Controlled marker {MARKER} was returned "
                f"in {context} context."
            ),
            detection_method=(
                "Controlled marker reflection and "
                "response-context analysis"
            ),
            exploitation_performed=False,
            recommendation=(
                "Apply contextual output encoding, "
                "template auto-escaping and strict input handling."
            ),
            difficulty=difficulty,
            assessment_mode=assessment_mode,
        )
    ]
