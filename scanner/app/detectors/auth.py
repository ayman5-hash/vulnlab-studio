import time
import uuid

from ..schemas import Finding


MAX_AUTH_PROBES = 5


async def detect(base, difficulty, client, assessment_mode="blackbox"):

    endpoint = "/login"

    observations = []

    unique = uuid.uuid4().hex[:8]

    # Exactly five or fewer controlled POST requests.
    for attempt in range(MAX_AUTH_PROBES):

        if difficulty == "easy" and attempt == 0:
            username = "lab-student"
        elif difficulty == "easy" and attempt == 1:
            username = f"unknown-lab-{unique}"
        else:
            username = f"vulnlab-probe-{unique}"

        started = time.perf_counter()

        response = await client.post(
            base + endpoint,
            params={
                "level": difficulty,
            },
            data={
                "username": username,
                "password": (
                    f"invalid-lab-{attempt}"
                ),
            },
            follow_redirects=False,
        )

        elapsed = (
            time.perf_counter()
            - started
        )

        observations.append({
            "attempt": attempt + 1,
            "username": username,
            "status": response.status_code,
            "elapsed": elapsed,
            "retry_after": response.headers.get(
                "Retry-After"
            ),
            "body": response.text[:120],
        })

    statuses = [
        item["status"]
        for item in observations
    ]

    retry_after_seen = any(
        item["retry_after"]
        for item in observations
    )

    lockout_seen = (
        429 in statuses
        or retry_after_seen
    )

    # ========================================================
    # EASY
    # ========================================================

    if difficulty == "easy":

        known_response = observations[0]["body"]
        unknown_response = observations[1]["body"]

        enumeration_signal = (
            known_response
            != unknown_response
        )

        confidence = 0.82

        evidence = (
            f"No lockout observed during "
            f"{MAX_AUTH_PROBES} bounded probes."
        )

        if enumeration_signal:

            confidence = 0.95

            evidence += (
                " Known and unknown usernames produced "
                "different authentication responses."
            )

        return [
            Finding(
                vulnerability=(
                    "Authentication Brute-Force "
                    "Resistance Weakness"
                ),
                endpoint=endpoint,
                parameter="username/password",
                severity="High",
                confidence=confidence,
                cwe="CWE-307",
                evidence=evidence,
                detection_method=(
                    "Bounded authentication response "
                    "and lockout analysis"
                ),
                exploitation_performed=False,
                recommendation=(
                    "Apply rate limiting, progressive delay, "
                    "controlled lockout, uniform failure "
                    "responses and MFA."
                ),
                difficulty=difficulty,
                assessment_mode=assessment_mode,
            )
        ]

    # ========================================================
    # MEDIUM
    # ========================================================

    if difficulty == "medium":

        if lockout_seen:
            return []

        elapsed_values = [
            item["elapsed"]
            for item in observations
        ]

        delay_growth = (
            max(elapsed_values)
            - min(elapsed_values)
        )

        return [
            Finding(
                vulnerability=(
                    "Partial Authentication "
                    "Rate-Limiting Weakness"
                ),
                endpoint=endpoint,
                parameter="username/password",
                severity="Medium",
                confidence=0.86,
                cwe="CWE-307",
                evidence=(
                    f"No lockout observed after "
                    f"{MAX_AUTH_PROBES} controlled probes. "
                    f"Timing spread={delay_growth:.3f}s."
                ),
                detection_method=(
                    "Bounded timing and lockout analysis"
                ),
                exploitation_performed=False,
                recommendation=(
                    "Combine progressive delay with "
                    "server-side throttling, controlled "
                    "lockout and MFA."
                ),
                difficulty=difficulty,
                assessment_mode=assessment_mode,
            )
        ]

    # ========================================================
    # HARD / EXPERT
    # ========================================================

    if lockout_seen:
        return []

    return [
        Finding(
            vulnerability=(
                "Authentication Lockout "
                "Control Not Observed"
            ),
            endpoint=endpoint,
            parameter="username/password",
            severity="Medium",
            confidence=0.78,
            cwe="CWE-307",
            evidence=(
                f"No 429 response or Retry-After header "
                f"was observed during "
                f"{MAX_AUTH_PROBES} controlled probes."
            ),
            detection_method=(
                "Bounded lockout-control assessment"
            ),
            exploitation_performed=False,
            recommendation=(
                "Implement server-side throttling, "
                "temporary lockout and MFA."
            ),
            difficulty=difficulty,
            assessment_mode=assessment_mode,
        )
    ]
