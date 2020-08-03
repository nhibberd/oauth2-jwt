Design
======

Will act as the source of truth for Authentication and Authorization.

It will be responsible for managing long lived API Keys as well as
granting short lived bearer tokens to access resources.


### Key decision factors

 - Optimise for compute to compute auth

 - Edge authorization latency

 - Decentralized validation of requests
