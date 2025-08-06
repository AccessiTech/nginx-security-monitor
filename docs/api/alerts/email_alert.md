# alerts.email_alert

## Functions

### load_email_config(config_path = None)

Load email configuration from YAML file.

**Parameters:**

- **config_path** = None

#### send_email_alert(alert_details, config_path = None)

Send email alert for security threats.

Args:
alert_details (dict): Dictionary containing alert information
config_path (str): Path to configuration file

**Parameters:**

- **alert_details**
- **config_path** = None

#### create_text_alert_body(alert_details)

Create plain text alert body.

**Parameters:**

- **alert_details**

#### create_html_alert_body(alert_details)

Create HTML alert body.

**Parameters:**

- **alert_details**

## Gmail SMTP Configuration

For Gmail SMTP to work, you need to:

1. **Enable 2-Factor Authentication** on your Gmail account
1. **Generate an App Password** for this application

To generate a Gmail App Password:

1. Go to your Google Account settings
1. Navigate to Security → 2-Step Verification → App passwords
1. Generate a new app password for "Mail"
1. Use this 16-character app password in your SMTP configuration instead of your regular password
