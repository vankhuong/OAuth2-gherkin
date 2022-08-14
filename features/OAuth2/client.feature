Feature: client
    In order to present information of an application, 
    which accesses protected resources
    As a system admin
    I want to store information of clients on a database

    The client could be hosted on a server, desktop, mobile or other device
    The client's information can be share for a specific application

    Rule: client types
    Two client types, based on their ability to
    authenticate securely with the authorization server
    See https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
    - confidential
    - public

    Background:
        Given there are clients:
            | identifier   | name                     | secret    | redirectUri                 | isConfidential | allowPkce | scopes               |
            | 3ad46227b2b4 | Client one: confidential | 61c97db5a | https://auth.local/callback | 1              | 0         | ["avatar", "email"]  |
            | d86ed78f9824 | Client two: public, PKCE | 41948fa30 | https://auth.local/callback | 0              | 1         | ["profile", "email"] |