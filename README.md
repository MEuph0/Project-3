# CSCE 3550  Project 3: Enhancing security and user management in the JWKS Server
Mason Willy

## Server
A server with 2 endpoints: a RESTful JWKS endpoint tht serves public keys in JWKS format and a /auth endpoint that returns an unexpired, signed JWT on a POST request. The code additionally has a POST endpoint to allow for new user registration. Auth endpoint interactions are also now logged.

## Database File
A SQLite based file that is populated with private keys, one expired and one valid, upon running the program. These keys are encrypted and decrypted with a generated Fernet key stored as a environment variable. Additional tables are almost now stored for user information and logging of the auth endpoint.

## Running the Program
The server can be ran with the follwoing command "py main.py" with Python3 and all requirements as outlined in the requirements.txt installed.

### Known Issues
Did not have time to implement the rate limiter for the auth endpoint but since it was optional not too worried about it.

## Testing Programs
To assist in the testing of the server, the desktop application Postman was utilized for ease of making POST and GET requests without using a web browser. This programs was also tested against the Gradebot numerous times ot guarantee its effectiveness.