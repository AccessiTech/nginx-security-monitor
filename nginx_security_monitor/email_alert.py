import smtplib
import yaml
import logging
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from nginx_security_monitor.config_manager import ConfigManager


def load_email_config(config_path=None):
    """Load email configuration from YAML file."""
    config_manager = ConfigManager.get_instance()

    # Use main config path if not provided, handle None robustly
    import os
    if not config_path:
        main_config_path = None
        if config_manager:
            main_config_path = getattr(config_manager, "config_path", None)
            if not main_config_path:
                try:
                    main_config_path = config_manager.get("alert_system.email.config_path", None)
                except Exception:
                    main_config_path = None
        # Use the first valid path that exists
        candidate_paths = [main_config_path, "config/settings.yaml", "config/service-settings.yaml"]
        config_path = next((p for p in candidate_paths if p and os.path.exists(p)), None)
        if not config_path:
            # Fallback to the first candidate if none exist
            config_path = candidate_paths[0]

    try:
        with open(config_path, "r") as file:
            config = yaml.safe_load(file)
            return config.get("email_service", {})
    except Exception as e:
        logging.error(f"Failed to load email config: {e}")
        return {}


def send_email_alert(alert_details, config_path=None):
    """
    Send email alert for security threats.

    Args:
        alert_details (dict): Dictionary containing alert information
        config_path (str): Path to configuration file
    """
    logger = logging.getLogger("nginx-security-monitor.email")
    config_manager = ConfigManager.get_instance()

    # Load configuration
    email_config = load_email_config(config_path)

    # Check if email alerts are enabled
    enabled = config_manager.get(
        "alert_system.email.enabled",
        email_config.get("enabled", False),
    )

    if not enabled:
        logger.info("Email alerts are disabled")
        return

    # Email configuration with ConfigManager fallbacks
    sender_email = config_manager.get(
        "alert_system.email.from_address",
        email_config.get("from_address", email_config.get("username")),
    )
    receiver_email = alert_details.get("recipient") or config_manager.get(
        "alert_system.email.to_address", email_config.get("to_address")
    )
    smtp_server = config_manager.get(
        "alert_system.email.smtp_server",
        email_config.get("smtp_server", "localhost"),
    )
    smtp_port = config_manager.get(
        "alert_system.email.smtp_port",
        email_config.get("smtp_port", 587),
    )
    username = config_manager.get(
        "alert_system.email.username", email_config.get("username")
    )
    password = config_manager.get(
        "alert_system.email.password", email_config.get("password")
    )
    use_tls = config_manager.get(
        "alert_system.email.use_tls",
        email_config.get("use_tls", True),
    )

    # Retry configuration
    retry_count = config_manager.get(
        "alert_system.email.retry_count", 3
    )  # Default to 3 attempts
    retry_delay = config_manager.get(
        "alert_system.email.retry_delay", 2
    )  # Default to 2 seconds

    # Debug level for SMTP connection
    debug_level = config_manager.get(
        "alert_system.email.debug_level", 0
    )  # Default to no debug

    if not all([sender_email, receiver_email]):
        logger.error("Missing email configuration")
        return

    # Prepare email content
    subject = alert_details.get(
        "subject", "Security Alert"
    )  # Default subject if not provided

    # Create HTML email body
    html_body = create_html_alert_body(alert_details)
    text_body = create_text_alert_body(alert_details)

    # Retry sending email with exponential backoff
    for attempt in range(retry_count):
        try:
            # Create the email message
            msg = MIMEMultipart("alternative")
            msg["From"] = sender_email
            msg["To"] = receiver_email
            msg["Subject"] = subject
            msg["Date"] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")

            # Add both text and HTML versions
            part1 = MIMEText(text_body, "plain")
            part2 = MIMEText(html_body, "html")

            msg.attach(part1)
            msg.attach(part2)

            # Add attachments if provided
            if "attachments" in alert_details and isinstance(
                alert_details["attachments"], list
            ):
                for attachment_path in alert_details["attachments"]:
                    try:
                        with open(attachment_path, "rb") as attachment:
                            part = MIMEBase("application", "octet-stream")
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)

                            # Add header as key/value pair to attachment part
                            part.add_header(
                                "Content-Disposition",
                                f"attachment; filename= {attachment_path.split('/')[-1]}",
                            )
                            msg.attach(part)
                    except Exception as e:
                        logger.error(f"Failed to attach file {attachment_path}: {e}")

            # Single attachment (backward compatibility)
            elif "attachment" in alert_details and alert_details["attachment"]:
                attachment_path = alert_details["attachment"]
                try:
                    with open(attachment_path, "rb") as attachment:
                        part = MIMEBase("application", "octet-stream")
                        part.set_payload(attachment.read())
                        encoders.encode_base64(part)

                        # Add header as key/value pair to attachment part
                        part.add_header(
                            "Content-Disposition",
                            f"attachment; filename= {attachment_path.split('/')[-1]}",
                        )
                        msg.attach(part)
                except Exception as e:
                    logger.error(f"Failed to attach file {attachment_path}: {e}")

            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.set_debuglevel(debug_level)

                if use_tls:
                    server.starttls()

                if username and password:
                    server.login(username, password)

                server.send_message(msg)

            logger.info(f"Email alert sent successfully to {receiver_email}")
            break  # Success, exit the retry loop

        except Exception as e:
            logger.error(
                f"Attempt {attempt+1}/{retry_count} to send email alert failed: {e}"
            )
            if attempt < retry_count - 1:
                import time

                # Exponential backoff with jitter
                sleep_time = retry_delay * (2**attempt) + (
                    random.random() * retry_delay
                )
                logger.info(f"Retrying in {sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
            else:
                logger.error(f"Failed to send email alert after {retry_count} attempts")
                # Consider additional fallback notification here
                try:
                    fallback_enabled = config_manager.get(
                        "alert_system.email.fallback_enabled",
                        False,
                    )
                    if fallback_enabled:
                        fallback_address = config_manager.get(
                            "alert_system.email.fallback_address"
                        )
                        if fallback_address and fallback_address != receiver_email:
                            logger.info(
                                f"Attempting to send to fallback address: {fallback_address}"
                            )
                            # Implementation of fallback notification would go here
                except Exception as fallback_error:
                    logger.error(f"Fallback notification failed: {fallback_error}")


def create_text_alert_body(alert_details):
    """Create plain text alert body."""
    config_manager = ConfigManager.get_instance()
    pattern = alert_details.get("pattern", "Unknown threat")
    timestamp = alert_details.get("timestamp", datetime.now().isoformat())

    # Get configurable elements from ConfigManager
    text_alert_header = config_manager.get(
        "alert_system.email.text_alert_header", "NGINX Security Alert"
    )
    action_text = config_manager.get(
        "alert_system.email.action_text", "Please investigate this threat immediately."
    )
    footer_text = config_manager.get(
        "alert_system.email.text_footer", "NGINX Security Monitor"
    )

    if isinstance(pattern, dict):
        threat_type = pattern.get("type", "Unknown")
        ip_address = pattern.get("ip", "Unknown")
        severity = pattern.get("severity", "UNKNOWN")
        request = pattern.get("request", "")

        # Get detailed text template from ConfigManager or use default
        detailed_text_template = config_manager.get(
            "alert_system.email.detailed_text_template",
            """
{text_alert_header} - {threat_type}

Threat Details:
- Type: {threat_type}
- Severity: {severity}
- Source IP: {ip_address}
- Timestamp: {timestamp}
- Request: {request}

{action_text}

--
{footer_text}
        """,
        ).strip()

        body = detailed_text_template.format(
            text_alert_header=text_alert_header,
            threat_type=threat_type,
            severity=severity,
            ip_address=ip_address,
            timestamp=timestamp,
            request=request,
            action_text=action_text,
            footer_text=footer_text,
        )
    else:
        # Get simple text template from ConfigManager or use default
        simple_text_template = config_manager.get(
            "alert_system.email.simple_text_template",
            """
{text_alert_header}

Threat Detected: {pattern}
Timestamp: {timestamp}

{action_text}

--
{footer_text}
        """,
        ).strip()

        body = simple_text_template.format(
            text_alert_header=text_alert_header,
            pattern=pattern,
            timestamp=timestamp,
            action_text=action_text,
            footer_text=footer_text,
        )

    return body


def create_html_alert_body(alert_details):
    """Create HTML alert body."""
    config_manager = ConfigManager.get_instance()
    pattern = alert_details.get("pattern", "Unknown threat")
    timestamp = alert_details.get("timestamp", datetime.now().isoformat())

    # Get configurable elements from ConfigManager
    alert_header = config_manager.get(
        "alert_system.email.alert_header", "🚨 Security Alert"
    )
    action_message = config_manager.get(
        "alert_system.email.action_message",
        "Please investigate this security threat immediately and take appropriate action to secure your system.",
    )
    footer_text = config_manager.get(
        "alert_system.email.footer_text",
        "This is an automated alert from your NGINX Security Monitor",
    )

    # Get severity colors from ConfigManager with defaults
    severity_colors = config_manager.get(
        "alert_system.email.severity_colors",
        {
            "HIGH": "#dc3545",  # Red
            "MEDIUM": "#fd7e14",  # Orange
            "LOW": "#ffc107",  # Yellow
        },
    )
    default_color = config_manager.get("alert_system.email.default_color", "#6c757d")

    # Format time for template
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(pattern, dict):
        threat_type = pattern.get("type", "Unknown")
        ip_address = pattern.get("ip", "Unknown")
        severity = pattern.get("severity", "UNKNOWN")
        request = pattern.get("request", "")

        # Color based on severity
        severity_color = severity_colors.get(severity, default_color)

        # Get template from ConfigManager or use default
        detailed_template = config_manager.get(
            "alert_system.email.detailed_template",
            """
<html>
<head></head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <div style="background-color: {severity_color}; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">{alert_header}</h1>
            <p style="margin: 5px 0 0 0; font-size: 16px;">{threat_type} Detected</p>
        </div>
        
        <div style="padding: 30px;">
            <h2 style="color: #333; margin-top: 0;">Threat Details</h2>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold; width: 30%;">Type:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{threat_type}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Severity:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">
                        <span style="background-color: {severity_color}; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">
                            {severity}
                        </span>
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Source IP:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-family: monospace;">{ip_address}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Timestamp:</td>
                    <td style="padding: 10px; border-bottom: 1px solid #eee;">{timestamp}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; font-weight: bold;">Request:</td>
                    <td style="padding: 10px; font-family: monospace; word-break: break-all;">{request}</td>
                </tr>
            </table>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;">
                    <strong>⚠️ Action Required:</strong> {action_message}
                </p>
            </div>
        </div>
        
        <div style="background-color: #f8f9fa; padding: 15px; text-align: center; color: #6c757d; font-size: 12px;">
            {footer_text}<br>
            Generated on {gen_time}
        </div>
    </div>
</body>
</html>
""",
        )

        html_body = detailed_template.format(
            severity_color=severity_color,
            alert_header=alert_header,
            threat_type=threat_type,
            severity=severity,
            ip_address=ip_address,
            timestamp=timestamp,
            request=request,
            action_message=action_message,
            footer_text=footer_text,
            gen_time=gen_time,
        )
    else:
        # Get simple template from ConfigManager or use default
        simple_template = config_manager.get(
            "alert_system.email.simple_template",
            """
<html>
<head></head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f8f9fa;">
    <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
        <div style="background-color: #dc3545; color: white; padding: 20px; text-align: center;">
            <h1 style="margin: 0; font-size: 24px;">{alert_header}</h1>
        </div>
        
        <div style="padding: 30px;">
            <h2 style="color: #333; margin-top: 0;">Threat Detected</h2>
            <p style="font-size: 16px; line-height: 1.5;">{pattern}</p>
            <p style="color: #6c757d;"><strong>Timestamp:</strong> {timestamp}</p>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 4px; padding: 15px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;">
                    <strong>⚠️ Action Required:</strong> {action_message}
                </p>
            </div>
        </div>
        
        <div style="background-color: #f8f9fa; padding: 15px; text-align: center; color: #6c757d; font-size: 12px;">
            {footer_text}
        </div>
    </div>
</body>
</html>
""",
        )

        html_body = simple_template.format(
            alert_header=alert_header,
            pattern=pattern,
            timestamp=timestamp,
            action_message=action_message,
            footer_text=footer_text,
        )

    return html_body
