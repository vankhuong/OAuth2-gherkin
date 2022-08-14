Feature: Authorize action
    In order to login with the authorization server 
    for a few important security benefits
    As a resource owner (end-user)
    I want to authenticate with the authorization server 
    and obtain an authorization code 

    Security benefits: the resource owner's credentials are never shared with the client
    Authorization code: see `auth_code.feature` file

    Rule: parameters
        - response_type: required
        - client_id: required
        - redirect_uri: optional
        - scope: optional
        - state: recommended

    Rule: security
        - The client MUST implement CSRF (Cross-site Request Forgery) protection for its redirect URI
          So the authorization server MUST implement CSRF protection for its authorization endpoint
          So a "state" parameter SHOULD be used for maintain state between the request and callback
          See the doc of this at https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
          See the guide to use "state" parameter at https://auth0.com/docs/secure/attack-protection/state-parameters
          See the explain using "state" parameter of Google Identify at https://developers.google.com/identity/protocols/oauth2/openid-connect?hl=en#createxsrftoken
          See a scenario of CSRF attack without state parameter at https://stackoverflow.com/a/35988614
        - With public client, the authorization server and the client MUST implement PKCE extension
    
    Background:
        When I go to auth server "/oauth2/authorize"

    Scenario: unsupported grant type
        When request with query string:
            | response_type | client_id    | code_challenge                              | code_challenge_method |
            | cod           | d86ed78f9824 | -4cf-Mzo_qg9-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM | S256                  |
        Then I receive status code 400
        And I have an error "unsupported_grant_type"

    Scenario: client not exist in registered
        When request with query string:
            | response_type | client_id    | code_challenge                              | code_challenge_method |
            | code          | cli000000000 | -4cf-Mzo_qg9-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM | S256                  |
        Then I receive status code 400
        And I have an error "client_not_found"

    Scenario: public client and no code challenge
        When request with query string:
            | response_type | client_id    |
            | code          | d86ed78f9824 |
        Then I receive status code 400
        And I have an error "invalid_request"
        And I have a hint "Code challenge must be provided for public clients"

    Scenario: redirect uri does not match
        When request with query string:
            | response_type | client_id    | redirect_uri                | code_challenge                              | code_challenge_method |
            | code          | d86ed78f9824 | https://auth.local/fallback | -4cf-Mzo_qg9-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM | S256                  |
        Then I receive status code 401
        And I have an error "invalid_client"

    Scenario: code challenge wrong
        When request with query string:
            | response_type | client_id    | code_challenge                             | code_challenge_method |
            | code          | d86ed78f9824 | 00000000000-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM | S256                  |
        Then I receive status code 400
        And I have an error "invalid_request"
        And I have a hint "Code challenge must follow the specifications of RFC-7636."

    Scenario: code challenge method wrong
        When request with query string:
            | response_type | client_id    | code_challenge                              | code_challenge_method |
            | code          | d86ed78f9824 | -4cf-Mzo_qg9-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM | S000                  |
        Then I receive status code 400
        And I have an error "invalid_request"
        And I have a hint "Code challenge method must be one of `S256`, `plain`"

    @success
    Scenario: authorize success
        When request with query string:
            | response_type | client_id    | redirect_uri | scope   | state | code_challenge                              | code_challenge_method |
            | code          | d86ed78f9824 | null         | profile | null  | -4cf-Mzo_qg9-uq0F4QwWhRh4AjcAqNx7SbYVsdmyQM | S256                  |
        Then I receive status code 302
        And I obtain authcode at "https://auth.local/callback?code="


    
