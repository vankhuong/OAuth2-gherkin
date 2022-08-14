Feature: scope
    In order to present information of all scopes to be used by clients, 
    As a system admin
    I want to store information of all scopes on a database

    See https://tools.ietf.org/html/rfc6749#section-3.3

    Background:
        Given there are scopes:
            | identifier |
            | avatar     |
            | profile    |
            | email      |