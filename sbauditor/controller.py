import getopt
import os
import sys

import boto3
import click

from insights import create_sechub_insights
from sbauditor import SBAuditor
from processor.main import get_providers, process_findings
from utility import get_credentials
import uuid
import json


def print_checks():
    app = SBAuditor(name="AWS Auditor")
    app.load_plugins()
    app.print_checks_md()


def run_auditor(auditor_name=None, check_name=None, delay=0, outputs=None, output_file=""):
    if not outputs:
        outputs = ["sechub"]
    app = SBAuditor(name="AWS Auditor")
    app.load_plugins(plugin_names=auditor_name)
    findings = list(app.run_checks(requested_check_name=check_name, delay=delay))
    # result = process_findings(findings=findings, outputs=outputs, output_file=output_file)
    return findings
    print(f"Done.")


@click.command()
@click.option("-p", "--profile-name", default="", help="User profile to use")
@click.option("-e", "--customer-id", default="", help="CustomerId")
@click.option("-f", "--account-number", default="", help="AccountNumber")
@click.option("-r", "--region", default="", help="region")
@click.option("-g", "--external-id", default="", help="External Id")
@click.option(
    "-a", "--auditor-name", default="", help="Auditor to test defaulting to all auditors"
)
@click.option("-c", "--check-name", default="", help="Check to test defaulting to all checks")
@click.option("-d", "--delay", default=0, help="Delay between auditors defaulting to 0")
@click.option(
    "-o",
    "--outputs",
    multiple=True,
    default=(["sechub"]),
    show_default=True,
    help="Outputs for findings",
)
@click.option("--output-file", default="output", show_default=True, help="File to output findings")
@click.option("--list-options", is_flag=True, help="List output options")
@click.option("--list-checks", is_flag=True, help="List all checks")
@click.option(
    "--create-insights",
    is_flag=True,
    help="Create SecurityHub insights for SecurityBot.  This only needs to be done once per SecurityHub instance",
)
def main(
    profile_name,
    customer_id,
    account_number,
    region,
    external_id,
    auditor_name,
    check_name,
    delay,
    outputs,
    output_file,
    list_options,
    list_checks,
    create_insights,
):
    if list_options:
        print(get_providers())
        sys.exit(2)

    if list_checks:
        print_checks()
        sys.exit(2)

    if profile_name:
        boto3.setup_default_session(profile_name=profile_name)

    if customer_id:
        print("Get customer account session")
        role_name = f"arn:aws:iam::{account_number}:role/MontyCloud-ApplicationRole"
        credentials = get_credentials(role_name, external_id)
        customer_account_credentials = {
            "aws_access_key_id": credentials['AccessKeyId'],
            "aws_secret_access_key": credentials['SecretAccessKey'],
            "aws_session_token":credentials['SessionToken'],
            "region_name": region
        }
        boto3.setup_default_session(**customer_account_credentials)

    if create_insights:
        create_sechub_insights()
        sys.exit(2)

    findings = run_auditor(
        auditor_name=auditor_name,
        check_name=check_name,
        delay=delay,
        outputs=outputs,
        output_file=output_file,
    )

    s3_data = {"Findings": findings}

    app_session = boto3.Session()
    s3_client = app_session.client("s3")
    report_id = str(uuid.uuid4())
    s3_key = f"{customer_id}/{account_number}/{region}/{report_id}.json"
    print(s3_key)

    param = {
        "Bucket": "mc-dev1-day2reports",
        "Key": s3_key,
        "Body": json.dumps(s3_data),
    }
    response = s3_client.put_object(**param)
    print("File written into s3 successfully")


if __name__ == "__main__":
    print(sys.argv[1:])
    main(sys.argv[1:])
