Feature: PKCE
    In order to support OAuth 2.0 public clients are susceptible 
    to the authorization code interception attack.
    As a client (application)
    I want to a couble code to verify the client request

    PKCE - Proof Key for Code Exchange by OAuth Public Clients
    See https://datatracker.ietf.org/doc/html/rfc7636
    See explain by PHP code at https://github.com/thephpleague/oauth2-server/blob/master/src/CodeChallengeVerifiers/S256Verifier.php

    The "code_challenge" and "code_challenge_method" values
    are stored in encrypted form in the "code" itself but could
    alternatively be stored on the server associated with the code

    Background: 
        Given there is "code_verifier" with value "01234567890123456789012345678901234567890123456789"
        And there is "code_challenge" with value "-4cf-Mzo_qg9-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM"
        And there is "code_challenge_method" with value "S256"