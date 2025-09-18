import datetime
from typing import Any, Mapping, Optional, Sequence, Tuple

from google.auth.transport import requests

from common import chronicle_auth
from common import datetime_converter
from common import regions

CHRONICLE_API_BASE_URL = "https://backstory.googleapis.com"


def list_detections(
    http_session: requests.AuthorizedSession,
    version_id: str,
    page_size: int = 0,
    page_token: str = "",
    start_time: Optional[datetime.datetime] = None,
    end_time: Optional[datetime.datetime] = None,
    list_basis: str = "",
    alert_state: str = "") -> Tuple[Sequence[Mapping[str, Any]], str]:
    url = f"{CHRONICLE_API_BASE_URL}/v2/detect/rules/{version_id}/detections"
    params_list = [
        ("page_size", page_size),
        ("page_token", page_token),
        ("start_time", datetime_converter.strftime(start_time)),
        ("end_time", datetime_converter.strftime(end_time)),
        ("list_basis", list_basis),
        ("alert_state", alert_state),
    ]

    params = {k: v for k, v in params_list if v}
    response = http_session.request("GET", url, params=params)
    
    if response.status_code >= 400:
        print(response.text)
    response.raise_for_status()
    j = response.json()
    return j.get("detections", []), j.get("nextPageToken", "")


def get_detections_for_rule(
    version_id: str,
    credentials_file: str,
    region: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    list_basis: str = "",
    alert_state: str = "") -> Tuple[list, str]:

    session = chronicle_auth.initialize_http_session(credentials_file)
    global CHRONICLE_API_BASE_URL
    CHRONICLE_API_BASE_URL = regions.url(CHRONICLE_API_BASE_URL, region)
    
    start_dt = datetime_converter.iso8601_datetime_utc(start_time) if start_time else None
    end_dt = datetime_converter.iso8601_datetime_utc(end_time) if end_time else None

    all_detections = []
    next_token = ""
    while True:
        detections, next_token = list_detections(
            http_session=session,
            version_id=version_id,
            page_size=1000,
            page_token=next_token,
            start_time=start_dt,
            end_time=end_dt,
            list_basis=list_basis,
            alert_state=alert_state
        )
        all_detections.extend(detections)
        if not next_token:
            break
    return all_detections, next_token


if __name__ == "__main__":
    cli = initialize_command_line_args()
    if not cli:
        sys.exit(1)
        
    session = chronicle_auth.initialize_http_session(cli.credentials_file)
    CHRONICLE_API_BASE_URL = regions.url(CHRONICLE_API_BASE_URL, cli.region)

    if cli.page_size or cli.page_token:
        detections, next_page_token = list_detections(
            session,
            cli.version_id,
            cli.page_size,
            cli.page_token,
            cli.start_time,
            cli.end_time,
            cli.list_basis,
            cli.alert_state
        )
        print(json.dumps(detections, indent=2))
        print(f"Next page token: {next_page_token}")
    else:
        detections, _ = get_detections_for_rule(
            cli.version_id,
            cli.credentials_file,
            cli.region,
            start_time=cli.start_time.isoformat() if cli.start_time else None,
            end_time=cli.end_time.isoformat() if cli.end_time else None,
            list_basis=cli.list_basis,
            alert_state=cli.alert_state
        )
        print(json.dumps(detections, indent=2))
