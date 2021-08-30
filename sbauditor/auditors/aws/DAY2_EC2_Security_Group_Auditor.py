import boto3
import datetime
from check_register import CheckRegister

registry = CheckRegister()

ec2 = boto3.client("ec2")

# loop through ec2 instances
def describe_instances(cache):
    response = cache.get("describe_instances")
    if response:
        return response
    cache["describe_instances"] = ec2.describe_instances(DryRun=False, MaxResults=1000)
    return cache["describe_instances"]


# loop through security groups
def describe_security_groups(cache):
    response = cache.get("describe_security_groups")
    if response:
        return response
    cache["describe_security_groups"] = ec2.describe_security_groups()
    return cache["describe_security_groups"]

@registry.register_check("ec2")
def any_port_open_to_the_internet(
    cache: dict, awsAccountId: str, awsRegion: str, awsPartition: str
) -> dict:
    instance_response = describe_instances(cache)
    sg_response = describe_security_groups(cache)
    myEc2InstanceReservations = instance_response["Reservations"]
    for reservations in myEc2InstanceReservations:
        for instances in reservations["Instances"]:
            instanceId = str(instances["InstanceId"])
            instanceArn = (
                f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:instance/{instanceId}"
            )
            instanceType = str(instances["InstanceType"])
            instanceImage = str(instances["ImageId"])
            instanceVpc = str(instances["VpcId"])
            instanceSubnet = str(instances["SubnetId"])
            instanceLaunchedAt = str(instances["LaunchTime"])
            for instanceSg in instances["SecurityGroups"]:
                sgName = str(instanceSg["GroupName"])
                sgId = str(instanceSg["GroupId"])
                sgArn = f"arn:{awsPartition}:ec2:{awsRegion}:{awsAccountId}:security-group/{sgId}"
                secgroup = next((sub for sub in sg_response["SecurityGroups"] if sub['GroupId'] == sgId), None)
                if not secgroup:
                    pass
                for permissions in secgroup["IpPermissions"]:
                    try:
                        fromPort = str(permissions["FromPort"])
                    except Exception as e:
                        if str(e) == "'FromPort'":
                            pass
                        else:
                            print(e)
                    try:
                        toPort = str(permissions["ToPort"])
                    except Exception as e:
                        if str(e) == "'ToPort'":
                            pass
                        else:
                            print(e)
                    try:
                        ipProtocol = str(permissions["IpProtocol"])
                    except Exception as e:
                        print(e)
                    ipRanges = permissions["IpRanges"]
                    for cidrs in ipRanges:
                        cidrIpRange = str(cidrs["CidrIp"])
                        iso8601Time = (
                            datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
                        )
                        if cidrIpRange == "0.0.0.0/0":
                            finding = {
                                "SchemaVersion": "2018-10-08",
                                "Id": instanceArn + "/" + ipProtocol + "/any-port-open-to-the-internet",
                                "ProductArn": f"arn:{awsPartition}:securityhub:{awsRegion}:{awsAccountId}:product/{awsAccountId}/default",
                                "GeneratorId": instanceArn,
                                "AwsAccountId": awsAccountId,
                                "Types": [
                                    "Software and Configuration Checks/AWS Security Best Practices",
                                    "Effects/Data Exposure",
                                ],
                                "FirstObservedAt": iso8601Time,
                                "CreatedAt": iso8601Time,
                                "UpdatedAt": iso8601Time,
                                "Severity": {"Label": "CRITICAL"},
                                "Confidence": 99,
                                "Title": "[Instance.1] Security group of instance has unrestricted access to some ports and protocols",
                                "Description": "Instance" + instanceId + "'s Security group "
                                + sgName
                                + " allows unrestricted access to some ports and protocols. Refer to the remediation instructions to remediate this behavior. Your security group should still be audited to ensure any other rules are compliant with organizational or regulatory requirements.",
                                "Remediation": {
                                    "Recommendation": {
                                        "Text": "For more information on modifying security group rules refer to the Adding, Removing, and Updating Rules section of the Amazon Virtual Private Cloud User Guide",
                                        "Url": "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#AddRemoveRules",
                                    }
                                },
                                "ProductFields": {"Product Name": "Day2SecurityBot"},
                                "Resources": [
                                    {
                                        "Type": "AwsEc2Instance",
                                        "Id": instanceArn,
                                        "Partition": awsPartition,
                                        "Region": awsRegion,
                                        "Details": {
                                            "AwsEc2Instance": {
                                                "Type": instanceType,
                                                "ImageId": instanceImage,
                                                "VpcId": instanceVpc,
                                                "SubnetId": instanceSubnet,
                                                # "LaunchedAt": instanceLaunchedAt,
                                                # "SecurityGroup": {"GroupName": sgName, "GroupId": sgId, },
                                            }
                                        },
                                    }
                                ],
                                "Compliance": {
                                    "Status": "FAILED",
                                    "RelatedRequirements": [
                                        "NIST CSF PR.AC-3",
                                        "NIST SP 800-53 AC-1",
                                        "NIST SP 800-53 AC-17",
                                        "NIST SP 800-53 AC-19",
                                        "NIST SP 800-53 AC-20",
                                        "NIST SP 800-53 SC-15",
                                        "AICPA TSC CC6.6",
                                        "ISO 27001:2013 A.6.2.1",
                                        "ISO 27001:2013 A.6.2.2",
                                        "ISO 27001:2013 A.11.2.6",
                                        "ISO 27001:2013 A.13.1.1",
                                        "ISO 27001:2013 A.13.2.1",
                                    ],
                                },
                                "Workflow": {"Status": "NEW"},
                                "RecordState": "ACTIVE",
                            }
                            yield finding

