# alerts.sms_alert

## Functions

### send_sms_alert(alert_details)

Sends an SMS alert with the provided details.

Parameters:
alert_details (dict): A dictionary containing alert information such as
'message', 'recipient', etc.

Returns:
bool: True if the SMS was sent successfully, False otherwise.

**Parameters:**

- **alert_details**

#### send_via_twilio(account_sid, auth_token, from_number, to_number, message)

Send SMS via Twilio API

**Parameters:**

- **account_sid**
- **auth_token**
- **from_number**
- **to_number**
- **message**

##### send_via_aws_sns(access_key, secret_key, phone_number, message)

Send SMS via AWS SNS

**Parameters:**

- **access_key**
- **secret_key**
- **phone_number**
- **message**
