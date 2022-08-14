Feature: Access token action
    In order to access protected resources
    As a resource owner
    I want to receive access token, refresh token from auth server

    Role: OAuth defines four grant types
        See https://datatracker.ietf.org/doc/html/rfc6749#section-1.3
        - Authorization code
        - Implicit (notice: this grant has a weak level of security, so not recommend used)
        - Password credentials
        - Client credentials

    Rule: technically
        - The client credentials grant type MUST only used by confidential clients
        - The client credentials grant or the client is a server application type, 
          the client MUST authenticate with the auth server for more security,
          see client authenticate at https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1
          see HTTP authenticate at https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication
        - Requested scopes MUST be in a registered client
        - Client's secret code only useful for confidential client type

    Background:
        When I go to auth server "/oauth2/access_token"

    Scenario: unknown grant type
        When request with parameters:
        | grant_type    | client_id    | client_secret |
        | unknown_grant | 3ad46227b2b4 | 61c97db5a     |
        Then I receive status code 400
        And I have an error "unsupported_grant_type"
    
    @scope
    Scenario: scope not in registered client
        When request with parameters:
        | grant_type         | client_id    | client_secret | scope          |
        | client_credentials | 3ad46227b2b4 | 61c97db5a     | avatar profile |
        Then I receive status code 400
        And I have an error "invalid_scope"
        And I have a hint "Check the `&quot;profile&quot;` scope"

    Scenario: confidential client with the secret code wrong
        When request with parameters:
        | grant_type         | client_id    | client_secret |
        | client_credentials | 3ad46227b2b4 | 00000000      |
        Then I receive status code 401
        And I have an error "invalid_client"

    @auth_code
    Scenario: authorization code cannot decrypt
        When request with parameters:
        | grant_type         | client_id    | code_verifier                                      | code                                 |
        | authorization_code | d86ed78f9824 | 01234567890123456789012345678901234567890123456789 | def50200de134deefbe0f0a4ca4f767c378f |
        Then I receive status code 400
        And I have an error "invalid_request"
        And I have a hint "Cannot decrypt the authorization code"

    @auth_code
    Scenario: authorization code expired
        When request with parameters:
        | grant_type         | client_id    | code_verifier                                      | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
        | authorization_code | d86ed78f9824 | 01234567890123456789012345678901234567890123456789 | def5020075cf241bd34ac6f557e1f9d772020b4512206f5620032ef04fd21cf231883f124c5de48c6e033b58e43d984c3e151bbf94e7efd404f21b469b827de1c8a06bfbeecd34562f91630f0b87a32ea72ae0d2c30ae93b5cf72f2b81e6ca86a2b3bbf90ed48ac06612714991d8ac5bf7fe85e15f5ccbd831c49d6ff67dd8307aed57c35c6d51af7a582721a4edcb64c20fc3bd382883bf58c4cec18fe14b51c2291468c79aa12cf8ae9aea71eef03dd58aade5d01b45bd231524590cbafbef01ab5df78097b8f1cab7e39211f52daf044de553f728f65fa6ff6a7b54fbe170f8ad24636da5e1b75ec1503c5a42bd5f0af1d0172872304c255498bdf2089dbd2f89263164fc6a3193e3291457f8b9d9686c9867e61ca608aa5e44b6b1540f0c6a5653e32c1340d66fa2e6d014a01676531e616e570ace6d037751e11929f083762a37601c24b2064e6acddc8416c2ff4468f3a3bc7880dd19e32924a44238e31a4a8b70a02143e13c913313162bb1909daaff340adbb33c003a7914bc2e80200279 |
        Then I receive status code 400
        And I have an error "invalid_request"
        And I have a hint "Authorization code has expired"

    @auth_code
    Scenario: authorization code revoked
        When request with parameters:
        | grant_type         | client_id    | code_verifier                                      | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
        | authorization_code | d86ed78f9824 | 01234567890123456789012345678901234567890123456789 | def502003de3a688f2f6bad8adcf548ef122c4938bcf141dcceb42f9f50a382ba957d602ea12d043921d491166eb63e67871d3ad2223f9bedcb85497818247091b3f957aa37519bd3e19fcc9dd0b05a8eb99c49bd51bf8a6c6bd20f14e7f81e58a394575f9aeaf4612f22ba11660cac0bcc75df2f77610dff9e3116287afc04ad0370f8c7fc0f0a5f587509369a0cd863ed7ef41b6c25a89e0a8f4b6d2a141c7a824c3165a407dd9281ae79b6e6449c4cdfe25e2b424da6e4d1e1afb7a8ea22aab4cc7a3051d9ed5554116b0131fae0a872c71090ca8b677b1595c426f4c32acbc6a2ab670e596994cd9b51192b0e829d292f4a167ea09733aedd80a48a6af9e6448b66e13e2040c1bebeff1cb8f98f6277c51763fa66e0ddc0657bf4dddcfc84b0fb571f541c51fe76c30e5a232f38f926fd4240f75fea3eed8c63c04854cf4f8b2643efb1631f09101ccfa3111935344f16b75ddb08e40292fd6cff5fce87e9e365e0edd9c6db5ef77f28ad30b5d349ce05fc0316e6d3395 |
        Then I receive status code 400
        And I have an error "invalid_request"
        And I have a hint "Authorization code has been revoked"

    @auth_code
    Scenario: code verifier wrong
        When request with parameters:
        | grant_type         | client_id    | code_verifier                                      | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
        | authorization_code | d86ed78f9824 | 00000000000123456789012345678901234567890123456789 | def50200de134deefbe2ddf18aa1036d33c713d5263d28882cfbbf45f9edbd371bc2dac0f3456dc0c7ce6872f81cc35d61e64be091fa22c78319c43f8c7329524992983e44fd310de1029f605ee658a65e417c66682cf4c4c54d6f01509a1a413284c3a26b85326d1c4815a8f792403b797267c6de21ebe0869eb57cea7c56c0a23eaeeae628d99f863c431c1ed967b2229c31680ce9d146eca03ebf67b639467eb738911b18a2f7a1811172625ef89a95bea154776edcfb4eceaeacd866d554a3b8920d91f450dc6a00f4f6760b4da858c4a6bdf3debafd14b87fb20947b9baa5a1150c0466ba87f36c23f4de5e2061782d36d75546e8b573e21fd8fa75ea7f0d31cf939ed2b5b37a26060f1378396a391c46bb41aed4ed01f8f74f00bcad893df8b3e68f776ea08e5727ab89edcf9c06b05b925927b0266b67e706d66de5aa4e95c242e071babe2563c0394d12840f30a897e3abd44350b47aa02b3c76377b5e946420d40e1259f4fc07458b6dfcefa0f0a4ca4f767c378f |
        Then I receive status code 400
        And I have an error "invalid_grant"
        And I have a hint "Failed to verify `code_verifier`."

    @auth_code @success
    Scenario: authorization code grant success
        When request with parameters:
        | grant_type         | client_id    | code_verifier                                      | code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
        | authorization_code | d86ed78f9824 | 01234567890123456789012345678901234567890123456789 | def50200de134deefbe2ddf18aa1036d33c713d5263d28882cfbbf45f9edbd371bc2dac0f3456dc0c7ce6872f81cc35d61e64be091fa22c78319c43f8c7329524992983e44fd310de1029f605ee658a65e417c66682cf4c4c54d6f01509a1a413284c3a26b85326d1c4815a8f792403b797267c6de21ebe0869eb57cea7c56c0a23eaeeae628d99f863c431c1ed967b2229c31680ce9d146eca03ebf67b639467eb738911b18a2f7a1811172625ef89a95bea154776edcfb4eceaeacd866d554a3b8920d91f450dc6a00f4f6760b4da858c4a6bdf3debafd14b87fb20947b9baa5a1150c0466ba87f36c23f4de5e2061782d36d75546e8b573e21fd8fa75ea7f0d31cf939ed2b5b37a26060f1378396a391c46bb41aed4ed01f8f74f00bcad893df8b3e68f776ea08e5727ab89edcf9c06b05b925927b0266b67e706d66de5aa4e95c242e071babe2563c0394d12840f30a897e3abd44350b47aa02b3c76377b5e946420d40e1259f4fc07458b6dfcefa0f0a4ca4f767c378f |
        Then I receive status code 200
        And I obtain access token "access_token"
        And I obtain refresh token "refresh_token"

    @client_credentials
    Scenario: client credentials grant with a public client
        When request with parameters:
        | grant_type         | client_id    | client_secret | scope  |
        | client_credentials | d86ed78f9824 | 41948fa30     | avatar |
        Then I receive status code 401
        And I have an error "invalid_client"

    @client_credentials @basic_auth @success
    Scenario: client credentials grant success
        When the parameters:
        | grant_type         | scope  |
        | client_credentials | avatar |
        And use basic auth with client id "3ad46227b2b4", secret "61c97db5a"
        Then I receive status code 200
        And I obtain access token "access_token"

    @password_grant
    Scenario: password credentials grant with username or password wrong
        When request with parameters:
        | grant_type | client_id    | username | password     |
        | password   | d86ed78f9824 | king.ngo | 123456random |
        Then I receive status code 400
        And I have an error "invalid_grant"

    @password_grant @success
    Scenario: password credentials grant success
        When request with parameters:
        | grant_type | client_id    | username | password |
        | password   | d86ed78f9824 | king.ngo | 123456   |
        Then I receive status code 200
        And I obtain access token "access_token"
        And I obtain refresh token "refresh_token"

    @refresh_token
    Scenario: refresh token revoked
        When request with parameters:
        | grant_type    | client_id    | refresh_token                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
        | refresh_token | d86ed78f9824 | def5020075eb7c71a492d6c26e7b509582c1e9c044ff5c98e2647c6b464112bd9f787a304ee9dcc1deddbacf7d4175aaf00d493fd9e7a815d67bb1b1c856355f33c3e02ae985053de87d821de52373cc07d61b1514ed621141d3b94a9b8e9627883afc6d8b689b71e44fc72b109eab2c15cbc711c8c1d0b5f8d5c7f212ae087a74e248c38e53a71d7dc362c6175fcbaaf9a641dce1a17b0520b00dfad0093170e5cc8c2440620e13766a7e9855679fe0744615b401923018e2fe46b0319cc9228ce74e20dcf874bbd9e6f46e8463f6bc922b91b1eb1409725a8cd41cb8baf1af74b0df6eb8a0284af2f23e28a49a2319be1c8037d914747ac218f04b1cf7e7afc2e881a71ff4b7f852f7f0da884646ed7326c2d85096c2de66e8786c7210b061771c3f7fdaebaff496a4d4a6c09160927201f06bffa4a78760c0009a7a28d991542a82f335ac7b7a1f0026e869294da030b8b446db1848385f8676670b2d56c6bdd67927cbcd781c7ba40c58d1fce24bf18f03a8373885058910b1c77c64214288 |
        Then I receive status code 401
        And I have an error "invalid_request"
        And I have a hint "Token has been revoked"

    @refresh_token
    Scenario: refresh token grant with a client wrong
        When request with parameters:
        | grant_type    | client_id    | client_secret | refresh_token                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
        | refresh_token | 3ad46227b2b4 | 61c97db5a     | def5020076bd0b462587026fe68e53ee1fe2d75d7015d3fce40cca06b8bfc8ea0ba5639c00845a45589a0f5b362101d06816645d0612dac6ac5122801a20e9a086183b5f7182e036e399e2ec7089fbec473664e2b8416b9e2e1c3c0929f9b2ebcb9d430bdc77759e861010f7ecd4c9723eacb1b65de0d162e4505c5060addff3b0a008f3060341997feb042a1459f4e5f160a95791bf14f4ac2139b1da762d07b2e5de1b1f67fe0a22863b95cd975533cfa8ca7358136677993a24d5b6e665e571bd3ebd878ff61f4fdbda92b79508beb1a6e4b22b94821e260ff98e865d1b20c573ed55cffd64c3f9039c6e22f8ff78b68aa87925a33f4bb6c34865b47596e384595cf7b7e7f5e7ae6039d364f39e1e47d887d127438ce4eea5fb495f407104b04f70c1feff28ab699c190b5f9ac588af857c618d9f0e27d1fc999c4b58ec94744a7f2e8f8b5ff5dfb631f3d1c617751159b338caff653a8684c138d2b6e94ccea91643366dead675b5ebae71dc94715d5b4598718f02492f41bc078b56c5c06f |
        Then I receive status code 401
        And I have an error "invalid_request"
        And I have a hint "Token is not linked to client"

    @refresh_token
    Scenario: refresh token wrong
        When request with parameters:
        | grant_type    | client_id    | refresh_token                 |
        | refresh_token | d86ed78f9824 | def5020076bd0b1bc078b56c5c06f |
        Then I receive status code 401
        And I have an error "invalid_request"
        And I have a hint "Cannot decrypt the refresh token"

    @refresh_token @success
    Scenario: refresh token grant success
        When request with parameters:
        | grant_type    | client_id    | refresh_token                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
        | refresh_token | d86ed78f9824 | def5020076bd0b462587026fe68e53ee1fe2d75d7015d3fce40cca06b8bfc8ea0ba5639c00845a45589a0f5b362101d06816645d0612dac6ac5122801a20e9a086183b5f7182e036e399e2ec7089fbec473664e2b8416b9e2e1c3c0929f9b2ebcb9d430bdc77759e861010f7ecd4c9723eacb1b65de0d162e4505c5060addff3b0a008f3060341997feb042a1459f4e5f160a95791bf14f4ac2139b1da762d07b2e5de1b1f67fe0a22863b95cd975533cfa8ca7358136677993a24d5b6e665e571bd3ebd878ff61f4fdbda92b79508beb1a6e4b22b94821e260ff98e865d1b20c573ed55cffd64c3f9039c6e22f8ff78b68aa87925a33f4bb6c34865b47596e384595cf7b7e7f5e7ae6039d364f39e1e47d887d127438ce4eea5fb495f407104b04f70c1feff28ab699c190b5f9ac588af857c618d9f0e27d1fc999c4b58ec94744a7f2e8f8b5ff5dfb631f3d1c617751159b338caff653a8684c138d2b6e94ccea91643366dead675b5ebae71dc94715d5b4598718f02492f41bc078b56c5c06f |
        Then I receive status code 200
        And I obtain access token "access_token"
        And I obtain refresh token "refresh_token"

