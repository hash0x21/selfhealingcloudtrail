import boto3

# WRI AWS Account ID to Alias Mapping 
ACCOUNTS = { 
    "074726884951":"lethal", 
}

# Static KMS Key ARN for CloudTrail Log Encryption 
KMS_KEY_ARN = "" # <--- PLACE KMS ARN FOR CLOUDTRAIL ENCRYPTION 
    
class CloudTrail(object):
    
    def __init__(self, trail_arn):
        self.client = boto3.client('cloudtrail')
        self.arn = trail_arn
        self.valid_config = {
            "Name":"{}-cloudtrail".format(account_name),
            "S3BucketName":"lethal-cloudtrail-logs",
            "S3KeyPrefix":"{}".format(account_name),
            "IncludeGlobalServiceEvents":True,
            "IsMultiRegionTrail":True,
            "EnableLogFileValidation":True,
            "CloudWatchLogsLogGroupArn":"arn:aws:logs:us-east-1:{}:log-group:/cloudtrail/{}/{}:*".format(account_id, account_name, account_id),
            "CloudWatchLogsRoleArn":"arn:aws:iam::{}:role/cloudtrail-{}-log-role".format(account_id, account_name),
            "KmsKeyId":KMS_KEY_ARN 
        }
        try:
            self.status = self.client.get_trail_status(Name=trail_arn)
            self.config = self.client.describe_trails(trailNameList=[self.arn])['trailList'][0]
        except:
            self.status = "N/A"
            self.config = "N/A" 
                    
    # Print CloudTrail Config & Status 
    def printTrail(self): 
        try: 
            print """[*] CloudTrail MetaData:
                Name: {}
                TrailARN: {}
                IncludeGlobalServiceEvents: {}
                LogFileValidationEnabled: {}
                IsMultiRegionTrail: {}
                KmsKeyId: {}
                S3BucketName: {}
                S3Prefix: {}
                IsLogging: {}
                TimeLoggingStarted: {}
                TimeLoggingStopped: {}\n""".format(
                self.config['Name'],
                self.config['TrailARN'],
                self.config['IncludeGlobalServiceEvents'],
                self.config['LogFileValidationEnabled'],
                self.config['IsMultiRegionTrail'],
                (self.config['KmsKeyId'] if 'KmsKeyId' in self.config.keys() else 'N/A'),        
                self.config['S3BucketName'],
                self.config['S3KeyPrefix'],        
                self.status['IsLogging'],
                self.status['TimeLoggingStarted'],
                self.status['TimeLoggingStopped']
            )
        except Exception as e:
            print "[*] Could Not Print Trail MetaData" 
            print e
                
    # Update CloudTrail Status
    def updateTrail(self):
        self.status = self.client.get_trail_status(Name=self.arn)
        self.config = self.client.describe_trails(trailNameList=[self.arn])['trailList'][0]
        return
            
    # Enable CloudTrail Logging 
    def enableTrail(self):
        try:
            response = self.client.start_logging(Name=self.arn)
            print "[*] SUCCESS: CloudTrail Logging Enabled"
            self.updateTrail()
            return True
        except Exception as e:
            print "[*] FAILED: CloudTrail Logging Disabled"
            print e
            return False
                    
    # Restore CloudTrail Configs    
    def restoreTrail(self):
        try:
            response = self.client.update_trail(**self.valid_config)
            print "[*] SUCCESS: CloudTrail Config Restored to Known Good State"
            self.updateTrail()
            return True
        except Exception as e:
            print "[*] FAILED: CloudTrail Config In Bad State"
            print e
            return False         
                            
    # Create New CloudTrail with Known Configs    
    def createTrail(self):
        try:
            response = self.client.create_trail(**self.valid_config)
            print "[*] SUCCESS: CloudTrail Created with Known Good Config"
            self.arn=response['TrailARN'] 
            self.enableTrail() 
            return True
        except Exception as e:
            print "[*] FAILED: CloudTrail Could NOT Be Created"
            print e
            return False                     


def lambda_handler(event, context):
    global account_id, account_name 
    
    print event 
    
    # Extract Details from AWS CloudTrail Event 
    trail_arn = event['detail']['requestParameters']['name']
    event_name = event['detail']['eventName']
    event_time = event['detail']['eventTime']
    useridentity_arn = event['detail']['userIdentity']['arn']
    user_api_key = event['detail']['userIdentity']['accessKeyId']
    user_agent = event['detail']['userAgent']
    user_name = event['detail']['userIdentity']['userName']
    account_id = event['account']
    account_name = ACCOUNTS[account_id]
            
    print """[*] CloudTrail Event Info:
        EventName: {}
        EventTime: {}
        UseridentityARN: {}
        AWSAccountAlias: {}
        AWSAccountID: {}
        UserAgent: {}\n""".format(
        event_name, 
        event_time,
        useridentity_arn, 
        account_name,
        account_id,
        user_agent
        ) 
    
    # If CloudTrail Update was from CloudWatchEvent or Terraform Update -- Break out of potential Infinite Loop 
    if "lambda-role" in useridentity_arn or "HashiCorp" in user_agent:
        print "CloudTrail update was initiated by CloudWatch Event / Terraform - Skip Logic"
        return 
    
    # Instantiate CloudTrail Object 
    trail_obj = CloudTrail(trail_arn) 

    # If CloudTrail was Stopped -- Re-Enable Logging 
    if event_name == "StopLogging":
        #trail_obj.printTrail()
        print "[*] CloudTrail Event was StopLogging. Re-Enabling CloudTrail Logging..." 
        trail_obj.enableTrail() 
                             
    # If CloudTrail was Updated -- Restore to Known Configurations 
    elif event_name == "UpdateTrail":
        #trail_obj.printTrail()
        print "[*] CloudTrail Event was UpdateTrail. Restoring CloudTrail Configs..." 
        trail_obj.restoreTrail()
            
    # If CloudTrail was Deleted -- Recreate CloudTrail with Known Configurations 
    elif event_name == "DeleteTrail":
        print "[*] CloudTrail Event was DeleteTrail. Recreating CloudTrail..." 
        trail_obj.createTrail()

    # Disable API Key 
    client = boto3.client('iam')
    client.update_access_key(AccessKeyId=user_api_key, Status='Inactive', UserName=user_name)
    
    # Output Updated CloudTrail Details 
    # trail_obj.printTrail()

