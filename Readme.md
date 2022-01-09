# Setup 
1. Clone the repository:
`git clone "https://github.com/huanderer/ZendeskSecurityChallenge_HuanJun.git"`

2. Update SSL version, Generate SSL certs and copy them into the certs folder:
`(For Debian Distros) sudo apt update; sudo apt install --only-upgrade openssl` 
`openssl req -x509 -newkey rsa:4096 -nodes -out certs/cert.pem -keyout certs/key.pem -days 365`

3. The password reset function requires that you set up a simple email server from which to send out password reset emails. You may sign up for an account here: https://signup.sendgrid.com/

4. Once you have signed up for an account, proceed to perform the necessary actions to verify the email address from which your reset emails will be sent out and generate an API key. 

5. Copy and paste the password and your verified email account into the .env file in the root directory. Verify that lines 47 to 51 of app.py accurately reflect the server, port and username details shown on your SendGrid page.  

6. You can then generate your flask secret key with the following command:
`python3 -c 'import secrets; print(secrets.token_hex())'`

7. Copy and paste this secret key into your config.py. This key will be used to cryptographically sign cookies and prevent malicious users from altering cookie values without the secret key. Keep this key safe. 

8. From the root directory, run the following command: `sudo docker build --tag SecureApp-docker .`.

9. Run your docker container with the following command: `sudo docker run -d -p 7999:7999 SecureApp-docker`. Your flask application should be good to go. 

# Visiting the Web Application:
1. The web application is hosted on port 7999 by default.

2. You may navigate to it through your browser by visiting "https://localhost:7999".

3. You will have to allow self-signed certificates in order to visit the web application. 

4. The "zendesk.sqlite" database will user account information and is empty by design. Sign up for an account to start exploring the application. 

# Features:
1. Input validation:
- Server-side (flask) username input validation to prevent SQL injections 
- Password Complexity validation in line with NIST 2021 Password Guidelines:
  - Minimum of 8 characters 
  - At least one 1 character from each character class (uppercase, lowercase, number, special character)
  - Daniel Miessler's Seclists top 10000 passwords check


2. Passwords stored as hashes:
- Uses werkzeug.security's generate_password_hash function (PBKDF2:sha256, salt length 16) to store only the hashes of the password to increase work factor required to conduct brute force attacks.


3. Prevention of timing attacks:
- Sleep function implemented on password reset function and login function to minimize exposure of side-channel information


4. Logging:
- Basic logging implemented with the `logging` library to track account lockout & POST/GET requests. Log is saved to "record.log" in the main project folder


5. CSRF Prevention:
- Implementation of CSRF tokens with `flask_wtf.csrf`


6. Mult-factor Authentiation:
- Implemented two-factor authentication with a Time-based One-Time-Password(OTP) by scanning a QR code with any free TOTP authenticator application (e.g. Google Authenticator) during the account setup process 


7. Password Reset Mechanism:
- In combination with a free Sendgrid account, implemented a password reset function where unauthenticated users can request for a password reset email. Limited to 100 emails a day
- Self password reset also provided for authenticated users. Requires knowledge of old password + email that was used to sign up


8. Account Lockout Mechanism:
- Account lockout counter saved in back-end, prevents possible brute force diddling
- 5 wrong password attempts result in a 15 minute lockout


9. HTTPS
- Self-signed certificates are used to encrypt communications to ensure data is protected from prying eyes
- Openssl should be updated to latest verson to prevent possible exploitation of heartbleed bug

10. Session Protection
- Maximum session time for logged-in user = 10 minutes
