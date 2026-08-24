import httpx

from fastapi.middleware.cors import CORSMiddleware

from fastapi import (
    FastAPI,
    HTTPException,
)

from fastapi.responses import FileResponse

from .crawler import crawl
from .schemas import ScanRequest
from .scope import target_allowed
from .whitebox import analyze
from .scoring import security_score
from .database import (
    init_db,
    save_scan,
    list_scans,
    get_scan,
)

from .reporting.report import generate_report

from .detectors import xss
from .detectors import sqli
from .detectors import lfi
from .detectors import traversal
from .detectors import rfi
from .detectors import auth


app = FastAPI(
    title="VulnLab Scanner API",
    version="0.3.0",
    description=(
        "Controlled vulnerability detection API "
        "for the isolated VulnLab environment."
    ),
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


DETECTORS = {
    "xss": xss.detect,
    "sqli": sqli.detect,
    "lfi": lfi.detect,
    "traversal": traversal.detect,
    "rfi": rfi.detect,
    "auth": auth.detect,
}


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def root():

    return {
        "name": "VulnLab Scanner API",
        "version": "0.3.0",
        "safe_mode": True,
        "detectors": list(
            DETECTORS.keys()
        ),
        "persistence": True,
    }


@app.get("/health")
def health():

    return {
        "status": "ok",
        "safe_mode": True,
        "detectors": len(DETECTORS),
        "persistence": True,
    }


@app.get("/scans")
def scans_history():

    return {
        "scans": list_scans(),
    }


@app.get("/scans/{scan_id}")
def scan_details(
    scan_id: int,
):

    scan = get_scan(
        scan_id
    )

    if not scan:

        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    return scan



@app.get("/reports/{scan_id}")
def download_report(scan_id: int):

    scan = get_scan(scan_id)

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found.",
        )

    try:
        pdf_path = generate_report(scan)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="PDF generation failed: " + str(exc),
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name,
    )


@app.post("/scans")
async def create_scan(
    body: ScanRequest,
):

    target = str(
        body.target
    ).rstrip("/")

    # ========================================================
    # SCOPE
    # ========================================================

    if not target_allowed(target):

        raise HTTPException(
            status_code=403,
            detail=(
                "Target rejected by VulnLab "
                "scope policy."
            ),
        )

    # ========================================================
    # WHITE BOX
    # ========================================================

    whitebox_hits = []

    if body.mode == "whitebox":

        if not body.source_path:

            raise HTTPException(
                status_code=400,
                detail=(
                    "source_path is required "
                    "for whitebox mode."
                ),
            )

        whitebox_hits = analyze(
            body.source_path
        )

    # ========================================================
    # CRAWLER
    # ========================================================

    crawl_result = await crawl(
        target,
        max_pages=30,
        difficulty=body.difficulty,
    )

    # ========================================================
    # MODULE SELECTION
    # ========================================================

    requested_modules = []

    for module in body.modules:

        if module not in DETECTORS:
            continue

        if module in requested_modules:
            continue

        requested_modules.append(
            module
        )

    # ========================================================
    # DETECTORS
    # ========================================================

    findings = []
    detector_errors = []

    async with httpx.AsyncClient(
        timeout=6.0,
        follow_redirects=True,
    ) as client:

        for module in requested_modules:

            detector = DETECTORS[
                module
            ]

            try:

                module_findings = (
                    await detector(
                        target,
                        body.difficulty,
                        client,
                        body.mode,
                    )
                )

                findings.extend(
                    module_findings
                )

            except Exception as exc:

                detector_errors.append({
                    "module": module,
                    "error": str(exc),
                })

    # ========================================================
    # SCORE
    # ========================================================

    score = security_score(
        findings
    )

    # ========================================================
    # PERSISTENCE
    # ========================================================

    scan_id = save_scan(
        target=target,
        mode=body.mode,
        difficulty=body.difficulty,
        status="completed",
        modules=requested_modules,
        security_score=score,
        crawl=crawl_result,
        findings=findings,
        whitebox_hits=whitebox_hits,
        detector_errors=detector_errors,
    )

    # ========================================================
    # RESULT
    # ========================================================

    return {
        "scan_id": scan_id,

        "target": target,
        "mode": body.mode,
        "difficulty": (
            body.difficulty
        ),

        "status": "completed",

        "modules": (
            requested_modules
        ),

        "crawl": crawl_result,

        "findings": [
            finding.model_dump()
            for finding in findings
        ],

        "finding_count": len(
            findings
        ),

        "security_score": score,

        "whitebox_hits": (
            whitebox_hits
        ),

        "detector_errors": (
            detector_errors
        ),

        "safe_mode": True,
    }
