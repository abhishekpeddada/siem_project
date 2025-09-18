"""Executable and reusable sample for listing detection rules.

API reference:
https://cloud.google.com/chronicle/docs/reference/detection-engine-api#listrules
"""

import argparse
import json
from typing import Any, Mapping, Sequence, Tuple

from google.auth.transport import requests

from common import chronicle_auth
from common import regions

CHRONICLE_API_BASE_URL = "https://backstory.googleapis.com"


def list_rules(
    http_session: requests.AuthorizedSession,
    page_size: int = 0,
    page_token: str = "",
    archive_state: str = "") -> Tuple[Sequence[Mapping[str, Any]], str]:

    url = f"{CHRONICLE_API_BASE_URL}/v2/detect/rules"
    params_list = [("page_size", page_size), ("page_token", page_token),
                   ("state", archive_state)]
    params = {k: v for k, v in params_list if v}

    response = http_session.request("GET", url, params=params)
    
    if response.status_code >= 400:
        print(response.text)
    response.raise_for_status()
    j = response.json()
    return j.get("rules", []), j.get("nextPageToken", "")

def get_all_rules(credentials_file: str, region: str, archive_state: str = "") -> list:

    session = chronicle_auth.initialize_http_session(credentials_file)
    global CHRONICLE_API_BASE_URL
    CHRONICLE_API_BASE_URL = regions.url(CHRONICLE_API_BASE_URL, region)
    all_rules = []
    next_token = ""
    while True:
        rules, next_token = list_rules(
            http_session=session,
            page_size=1000,
            page_token=next_token,
            archive_state=archive_state
        )
        all_rules.extend(rules)
        if not next_token:
            break
    return all_rules


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    chronicle_auth.add_argument_credentials_file(parser)
    regions.add_argument_region(parser)
    parser.add_argument(
        "-s",
        "--page_size",
        type=int,
        required=False,
        help="maximum number of rules to return")
    parser.add_argument(
        "-t",
        "--page_token",
        type=str,
        required=False,
        help="page token from a previous ListRules call used for pagination")
    parser.add_argument(
        "-as",
        "--archive_state",
        type=str,
        required=False,
        help="archive state (i.e. 'ACTIVE', 'ARCHIVED', 'ALL')")

    args = parser.parse_args()
    
    if args.page_size or args.page_token or args.archive_state:
        session = chronicle_auth.initialize_http_session(args.credentials_file)
        CHRONICLE_API_BASE_URL = regions.url(CHRONICLE_API_BASE_URL, args.region)
        rules, next_page_token = list_rules(session, args.page_size, args.page_token, args.archive_state)
        print(json.dumps(rules, indent=2))
        print(f"Next page token: {next_page_token}")
    else:
        rules = get_all_rules(args.credentials_file, args.region)
        print(json.dumps(rules, indent=2))
