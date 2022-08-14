Feature: Refresh token
    In order to present information of refresh token
    As a system admin
    I want to store information of refresh token in a database

    Refresh tokens are credentials used to obtain access token
    and are issued to the client by authorization server,
    useful when the current access token becomes invalid or expires,
    see https://datatracker.ietf.org/doc/html/rfc6749#section-1.5

    Background:
        Given there are refresh tokens:
        | identifier                                                                       | expiryDateTime | access_token_identifier                                                          |
        | ca549094a3a48f7a890cfc0668996cf93261976e42296d37470281a1fa3b6d915efb7de654caf054 | P36M           | d55d86b1340b0ff85651a00aae88170c78e754c279818a1d0814216e23be749fa9b0b3af1f62a6bf |
        | 491bfb88d69829d0bcbced448edf38f0f1e3149f7573ed7ac169466d30e7b593d4b372345985615e | P36M           | 8d423eb4f2b3f81a5e8d9713dccc48aebc67c54203fcc3190334b74d2974015e9b77e7838827f85f |
