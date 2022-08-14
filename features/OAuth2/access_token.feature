Feature: Access token
    In order to present information of issued access tokens
    As a system admin
    I want to store information of access token in a database

    Access tokens are credentials used to access protected resources
    An access token is a string representing an authorization issued to the client
    See https://datatracker.ietf.org/doc/html/rfc6749#section-1.4

    Background:
        Given there are access tokens:
        | client_identifier | userIdentifier | expiryDateTime | scopes               | revoke | identifier                                                                       |
        | d86ed78f9824      | 11111          | P36M           | ["profile", "email"] | 0      | d55d86b1340b0ff85651a00aae88170c78e754c279818a1d0814216e23be749fa9b0b3af1f62a6bf |
