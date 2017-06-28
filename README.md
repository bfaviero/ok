# ok

http://css.csail.mit.edu/6.858/2014/projects/kanter-bcyphers-bfaviero-jpeebles.pdf

Kerberos is a powerful, convenient framework for user authentication and authorization. Within MIT, Kerberos is used with
many online institute services to verify users as part of Project Athena. However, it can be difficult for developers unfamiliar
with Kerberos development to take advantage of its resources for use in third-party apps.

OAuth 2.0 is an open source protocol used across the web for secure delegated access to resources on a server. Designed to
be developer-friendly, OAuth is the de facto standard for authenticating users across sites, and is used by services including
Google, Facebook, and Twitter.

Our goal with OK Server is to provide an easy way for developers to access third-party services using Kerberos via OAuth.
The benefits of this are twofold: developers can rely on an external service for user identification and verification, and users
only have to trust a single centralized server with their credentials. Additionally, developers can request access to a subset of
Kerberos services on behalf of a user.
