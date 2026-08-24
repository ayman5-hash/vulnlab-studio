from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

import httpx
from bs4 import BeautifulSoup


def normalize_url_for_level(
    url: str,
    difficulty: str | None,
) -> str:
    """
    Keep only the requested VulnLab difficulty when a
    URL contains a `level` query parameter.

    Other query parameters are preserved.
    """

    if not difficulty:
        return url

    parsed = urlparse(url)

    params = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    if not any(
        name == "level"
        for name, _ in params
    ):
        return url

    updated = []

    for name, value in params:
        if name == "level":
            updated.append(
                ("level", difficulty)
            )
        else:
            updated.append(
                (name, value)
            )

    return urlunparse(
        parsed._replace(
            query=urlencode(
                updated,
                doseq=True,
            )
        )
    )


def same_origin(
    candidate: str,
    origin,
) -> bool:

    parsed = urlparse(candidate)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        return False

    if parsed.hostname != origin.hostname:
        return False

    candidate_port = (
        parsed.port
        or (
            443
            if parsed.scheme == "https"
            else 80
        )
    )

    origin_port = (
        origin.port
        or (
            443
            if origin.scheme == "https"
            else 80
        )
    )

    return candidate_port == origin_port


async def crawl(
    start_url: str,
    max_pages: int = 30,
    difficulty: str | None = None,
):

    start_url = normalize_url_for_level(
        start_url,
        difficulty,
    )

    origin = urlparse(start_url)

    visited = set()
    queued = {start_url}
    queue = [start_url]

    pages = []
    endpoints = []
    parameters = set()
    forms = []

    seen_forms = set()

    async with httpx.AsyncClient(
        timeout=5.0,
        follow_redirects=True,
    ) as client:

        while (
            queue
            and len(visited) < max_pages
        ):

            url = queue.pop(0)
            queued.discard(url)

            url = normalize_url_for_level(
                url,
                difficulty,
            )

            if url in visited:
                continue

            visited.add(url)

            try:
                response = await client.get(
                    url
                )

            except Exception as exc:

                pages.append({
                    "url": url,
                    "status": None,
                    "error": str(exc),
                })

                continue

            final_url = normalize_url_for_level(
                str(response.url),
                difficulty,
            )

            pages.append({
                "url": final_url,
                "status": response.status_code,
                "content_type": (
                    response.headers.get(
                        "content-type",
                        "",
                    )
                ),
                "length": len(
                    response.content
                ),
            })

            parsed_current = urlparse(
                final_url
            )

            endpoints.append({
                "path": (
                    parsed_current.path
                    or "/"
                ),
                "method": "GET",
            })

            for name, _ in parse_qsl(
                parsed_current.query,
                keep_blank_values=True,
            ):
                parameters.add(name)

            content_type = (
                response.headers.get(
                    "content-type",
                    "",
                )
            )

            if "text/html" not in content_type:
                continue

            soup = BeautifulSoup(
                response.text,
                "html.parser",
            )

            # =================================================
            # LINKS
            # =================================================

            for tag in soup.find_all(
                "a",
                href=True,
            ):

                candidate = urljoin(
                    final_url,
                    tag["href"],
                )

                candidate = (
                    normalize_url_for_level(
                        candidate,
                        difficulty,
                    )
                )

                if not same_origin(
                    candidate,
                    origin,
                ):
                    continue

                if (
                    candidate not in visited
                    and candidate not in queued
                ):
                    queue.append(
                        candidate
                    )

                    queued.add(
                        candidate
                    )

            # =================================================
            # FORMS
            # Passive discovery only.
            # =================================================

            for form in soup.find_all(
                "form"
            ):

                method = form.get(
                    "method",
                    "GET",
                ).upper()

                action = urljoin(
                    final_url,
                    form.get("action")
                    or final_url,
                )

                action = (
                    normalize_url_for_level(
                        action,
                        difficulty,
                    )
                )

                if not same_origin(
                    action,
                    origin,
                ):
                    continue

                inputs = []

                for input_tag in (
                    form.find_all(
                        [
                            "input",
                            "textarea",
                            "select",
                        ]
                    )
                ):

                    name = input_tag.get(
                        "name"
                    )

                    if not name:
                        continue

                    inputs.append(name)
                    parameters.add(name)

                form_key = (
                    action,
                    method,
                    tuple(sorted(inputs)),
                )

                if form_key not in seen_forms:

                    seen_forms.add(
                        form_key
                    )

                    forms.append({
                        "action": action,
                        "method": method,
                        "inputs": inputs,
                    })

                endpoints.append({
                    "path": (
                        urlparse(action).path
                        or "/"
                    ),
                    "method": method,
                })

    # =========================================================
    # ENDPOINT DEDUPLICATION
    # =========================================================

    unique_endpoints = []
    seen_endpoints = set()

    for endpoint in endpoints:

        key = (
            endpoint["path"],
            endpoint["method"],
        )

        if key in seen_endpoints:
            continue

        seen_endpoints.add(key)

        unique_endpoints.append(
            endpoint
        )

    return {
        "start_url": start_url,
        "difficulty": difficulty,
        "visited_pages": len(
            visited
        ),
        "pages": pages,
        "endpoints": unique_endpoints,
        "parameters": sorted(
            parameters
        ),
        "forms": forms,
    }
