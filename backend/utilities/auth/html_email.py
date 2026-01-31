def create_verification_email_html(verification_code):
    """
    Generates the HTML string for a verification code email.

    Args:
        verification_code (str): The 6-digit verification code to be included in the email.

    Returns:
        str: The complete HTML string for the email.
    """
    html_string = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Verification Code</title>
    <style>
        /* Dark Mode styles for clients that support it */
        @media (prefers-color-scheme: dark) {{
            body {{ background-color: #121212 !important; }}
            .main-table {{ background-color: #1e1e1e !important; }}
            .title, .text, .code-text, .footer-text {{ color: #e0e0e0 !important; }}
            .code-container {{ background-color: #333333 !important; }}
            .footer-cell {{ background-color: #262626 !important; }}
            /* Specific overrides for mail clients that use a class for dark mode */
            [data-ogsc] .main-table, [data-ogsc] .footer-cell {{
                background-color: #1e1e1e !important;
            }}
        }}
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td style="padding: 20px 0;">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="600" class="main-table" style="margin: auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <tr>
                        <td style="padding: 40px; text-align: center;">
                            <h1 class="title" style="color: #333333; font-size: 28px; font-weight: bold; margin: 0 0 20px 0;">Cyberultron Consulting Pvt Ltd</h1>
                            <p class="text" style="color: #666666; font-size: 16px; line-height: 1.5; margin: 0 0 20px 0;">
                                Hi there,
                                <br><br>
                                You recently requested a verification code to access your account. Please use the code below to complete your verification.
                            </p>
                            <div class="code-container" style="background-color: #e8e8e8; border-radius: 6px; padding: 20px; display: inline-block;">
                                <h2 class="code-text" style="color: #333333; font-size: 36px; font-weight: bold; margin: 0; letter-spacing: 5px;">
                                    {verification_code}
                                </h2>
                            </div>
                            <p class="text" style="color: #666666; font-size: 14px; line-height: 1.5; margin: 20px 0 0 0;">
                                This code is only valid for a limited time.
                                <br>
                                If you did not request this, please disregard this email.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td class="footer-cell" style="background-color: #f8f8f8; padding: 20px; text-align: center; border-top: 1px solid #e0e0e0;">
                            <p class="footer-text" style="color: #999999; font-size: 12px; margin: 0;">
                                &copy; 2024 Cyberultron Consulting Pvt Ltd. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    return html_string


def create_user_password_email_html(password, email):
    """
    Generates the HTML string for an email that sends the user their password and email to login.
    """
    html_string = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <title>User Password and Email</title>
    </head>
    <body>
        <h1>User Password</h1>
        <p>Your password is: <strong>{password}</strong></p>
        <p>Your email is: {email}</p>
        <p>You can use this password to login to your account.</p>
        <p>Please keep this password secure and do not share it with anyone.</p>
        <p>If you have any questions, please contact us at <a href="mailto:support@cyberultron.com">support@cyberultron.com</a>.</p>
        <p>Thank you for using our service.</p>
        <p>Best regards,</p>
        <p>Cyberultron Consulting Pvt Ltd</p>
    </body>
    </html>
    """
    return html_string


def create_user_password_email_html_for_team_membership(password, email, team_name):
    """
    Generates the HTML string for an email that sends the user their username and password
    to log in after being invited to join a team.
    """
    html_string = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Team Invitation - Your Login Details</title>
    <style>
        @media (prefers-color-scheme: dark) {{
            body {{ background-color: #121212 !important; }}
            .main-table {{ background-color: #1e1e1e !important; }}
            .title, .text, .credential-label, .credential-value, .footer-text {{ color: #e0e0e0 !important; }}
            .credential-box {{ background-color: #333333 !important; border-color: #444 !important; }}
            .footer-cell {{ background-color: #262626 !important; }}
        }}
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td style="padding: 20px 0;">
                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="600" class="main-table" style="margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                    <tr>
                        <td style="padding: 40px; text-align: center;">
                            <h1 class="title" style="color: #333333; font-size: 28px; font-weight: bold; margin: 0 0 20px 0;">Cyberultron Consulting Pvt Ltd</h1>
                            <p class="text" style="color: #666666; font-size: 16px; line-height: 1.5; margin: 0 0 20px 0;">
                                You have been invited to join the team <strong>"{team_name}"</strong>.
                            </p>
                            <p class="text" style="color: #666666; font-size: 16px; line-height: 1.5; margin: 0 0 24px 0;">
                                Use the credentials below to log in to your account:
                            </p>
                            <div style="text-align: left;">
                                <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" class="credential-box" style="margin: 0 auto; background-color: #e8e8e8; border-radius: 6px; padding: 24px; border: 1px solid #ddd;">
                                    <tr>
                                        <td class="credential-label" style="color: #333333; font-size: 14px; font-weight: bold; padding: 8px 0 4px 0; text-align: left;">Username (email)</td>
                                    </tr>
                                    <tr>
                                        <td class="credential-value" style="color: #333333; font-size: 16px; padding: 0 0 16px 0; word-break: break-all; text-align: left;">{email}</td>
                                    </tr>
                                    <tr>
                                        <td class="credential-label" style="color: #333333; font-size: 14px; font-weight: bold; padding: 8px 0 4px 0; text-align: left;">Password</td>
                                    </tr>
                                    <tr>
                                        <td class="credential-value" style="color: #333333; font-size: 16px; font-weight: bold; padding: 0; text-align: left;">{password}</td>
                                    </tr>
                                </table>
                            </div>
                            <p class="text" style="color: #666666; font-size: 14px; line-height: 1.5; margin: 20px 0 0 0;">
                                Please keep these credentials secure and do not share them with anyone.
                                <br>
                                If you did not expect this invitation, please disregard this email.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td class="footer-cell" style="background-color: #f8f8f8; padding: 20px; text-align: center; border-top: 1px solid #e0e0e0;">
                            <p class="footer-text" style="color: #999999; font-size: 12px; margin: 0;">
                                &copy; 2024 Cyberultron Consulting Pvt Ltd. All rights reserved.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    return html_string

# Example usage:
if __name__ == "__main__":
    # Generate a random 6-digit code for demonstration
    import random
    code = ''.join(random.choices('0123456789', k=6))
    
    # Get the HTML string with the generated code
    email_html = create_verification_email_html(code)

    # Print the HTML string
    print(email_html)
    
    # You could save this string to a file or send it via a mailing service
    # with open("verification_email_final.html", "w") as f:
    #     f.write(email_html)
