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
