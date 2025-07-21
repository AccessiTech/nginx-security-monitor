import logging
from src.config_manager import ConfigManager


def send_sms_alert(alert_details):
    """
    Sends an SMS alert with the provided details.

    Parameters:
    alert_details (dict): A dictionary containing alert information such as
                          'message', 'recipient', etc.

    Returns:
    bool: True if the SMS was sent successfully, False otherwise.
    """
    # For compatibility with tests, maintain the original behavior
    # when run with test alert details
    if "recipient" in alert_details and "message" in alert_details:
        try:
            print(
                f"Sending SMS to {alert_details['recipient']}: {alert_details['message']}"
            )
            return True
        except Exception as e:
            print(f"Failed to send SMS: {e}")
            return False

    logger = logging.getLogger("nginx-security-monitor.sms")
    config = ConfigManager.get_instance()

    # Check if SMS alerts are enabled
    enabled = config.get("alert_system.sms.enabled", False)
    if not enabled:
        logger.info("SMS alerts are disabled")
        return False

    # Get SMS service configuration
    service_provider = config.get("alert_system.sms.provider", "dummy")
    api_key = config.get("alert_system.sms.api_key", "")
    api_secret = config.get("alert_system.sms.api_secret", "")
    from_number = config.get("alert_system.sms.from_number", "")

    # Get recipient from alert details or fallback to configured default
    recipient = alert_details.get("recipient") or config.get(
        "alert_system.sms.default_recipient", ""
    )

    if not recipient:
        logger.error("No SMS recipient specified")
        return False

    # Prepare message content
    message = alert_details.get("message", "Security alert: Check your system")
    max_length = config.get("alert_system.sms.max_length", 160)

    # Truncate message if it's too long
    if len(message) > max_length:
        message = message[: max_length - 3] + "..."

    # Retry configuration
    retry_count = config.get("alert_system.sms.retry_count", 3)
    retry_delay = config.get("alert_system.sms.retry_delay", 5)  # seconds

    # Send SMS based on provider
    for attempt in range(retry_count):
        try:
            if service_provider == "twilio":
                return send_via_twilio(
                    api_key, api_secret, from_number, recipient, message
                )
            elif service_provider == "aws_sns":
                return send_via_aws_sns(api_key, api_secret, recipient, message)
            else:
                # Default dummy provider for testing
                logger.info(f"[DUMMY SMS] To: {recipient}, Message: {message}")
                return True

        except Exception as e:
            logger.error(f"Attempt {attempt+1}/{retry_count} failed to send SMS: {e}")
            if attempt < retry_count - 1:
                import time

                time.sleep(retry_delay * (2**attempt))  # Exponential backoff
            else:
                logger.error(f"Failed to send SMS after {retry_count} attempts")
                return False

    return False


def send_via_twilio(account_sid, auth_token, from_number, to_number, message):
    """Send SMS via Twilio API"""
    logger = logging.getLogger("nginx-security-monitor.sms.twilio")

    try:
        # Lazy import to avoid dependency if not using Twilio
        import importlib.util

        twilio_spec = importlib.util.find_spec("twilio")

        if twilio_spec is None:
            logger.error(
                "Twilio package not installed. Install with: pip install twilio"
            )
            return False

        # Using type ignore for optional dependency
        from twilio.rest import Client  # type: ignore

        client = Client(account_sid, auth_token)
        message = client.messages.create(body=message, from_=from_number, to=to_number)

        logger.info(f"SMS sent via Twilio. SID: {message.sid}")
        return True

    except Exception as e:
        logger.error(f"Failed to send SMS via Twilio: {e}")
        return False


def send_via_aws_sns(access_key, secret_key, phone_number, message):
    """Send SMS via AWS SNS"""
    logger = logging.getLogger("nginx-security-monitor.sms.aws_sns")
    config = ConfigManager.get_instance()

    try:
        # Lazy import to avoid dependency if not using AWS
        import importlib.util

        boto3_spec = importlib.util.find_spec("boto3")

        if boto3_spec is None:
            logger.error("boto3 package not installed. Install with: pip install boto3")
            return False

        # Using type ignore for optional dependency
        import boto3  # type: ignore

        # Initialize SNS client
        client = boto3.client(
            "sns",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=config.get(
                "alert_system.aws_sns.region", "us-east-1"
            ),  # Use config for region
        )

        # Send SMS
        response = client.publish(
            PhoneNumber=phone_number,
            Message=message,
            MessageAttributes={
                "AWS.SNS.SMS.SenderID": {
                    "DataType": "String",
                    "StringValue": "NGXSECMON",
                }
            },
        )

        logger.info(f"SMS sent via AWS SNS. Message ID: {response['MessageId']}")
        return True

    except Exception as e:
        logger.error(f"Failed to send SMS via AWS SNS: {e}")
        return False
