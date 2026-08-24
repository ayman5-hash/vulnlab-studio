from pathlib import Path
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML


BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(__file__).resolve().parents[3]
REPORTS_DIR = PROJECT_ROOT / "reports"


def generate_report(scan: dict) -> Path:
    REPORTS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    env = Environment(
        loader=FileSystemLoader(
            str(BASE_DIR)
        ),
        autoescape=True,
    )

    template = env.get_template(
        "template.html"
    )

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    html = template.render(
        scan=scan,
        generated_at=generated_at,
    )

    output_path = (
        REPORTS_DIR
        / f"vulnlab-scan-{scan['id']}.pdf"
    )

    HTML(
        string=html,
        base_url=str(BASE_DIR),
    ).write_pdf(
        str(output_path)
    )

    return output_path
