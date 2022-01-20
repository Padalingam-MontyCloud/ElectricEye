import boto3

class STS(object):
    def __init__(self):
        self.app_session = None
        self.sts_client = None

    def configure(self, session):
        self.app_session = session
        self.sts_client = self.app_session.client('sts')

    def assume_role(self, role_arn, external_id):
        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                ExternalId=external_id,
                RoleSessionName='assumed_role',
                DurationSeconds=3600,
                # SerialNumber='string',
                # Policy='string',
                # TokenCode='string'
            )
            return response
        except Exception as e:
            raise e

    def get_credentials(self, role_arn, external_id):
        try:
            response = self.assume_role(role_arn, external_id)
            credentials = response['Credentials']
            return credentials
        except Exception as e:
            raise e


def get_credentials(role_name, external_id):
    try:
        app_session = boto3.Session()
        sts = STS()
        sts.configure(app_session)
        credentials = sts.get_credentials(role_name, external_id)
        return credentials
    except Exception as e:
        raise e