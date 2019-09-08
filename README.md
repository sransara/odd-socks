# Odd socks
Implementation of [SOCKS 5 protocol](https://www.ietf.org/rfc/rfc1928.txt) in Go.

# Usage
``` sh
> go get github.com/sransara/oddsocks
> oddsocks -h
Usage of oddsocks:
    -laddr string
        Specify host:port to listen for incoming SOCKS connections (default ":0")
```

# Features

- No configuration (rulesets, username/password etc.) bells and whistles
- Make your own customization by injecting appropriate state handler or action into the state machine
- [-] Auth Methods
    - [X] No authentication
    - [ ] Username/password
    - [ ] GSSAPI
- [X] Address Type
    - [X] IPv4
    - [X] IPv6
    - [X] Domain name
- [-] Commands
    - [X] Connect : production ready
    - [X] Bind : see Issues section
    - [-] UDP associate : see Issues section
        - [-] Fragment support : assuming single fragment


# Issues
- Need functional testing for BIND command (#1)
- Need functional testing for UDP ASSOC command (#2)
- Automated integration test suite (#3)
- Add UDP Fragment support (#4)
- Implement socks relay (#5)
- Better strategy for state handler and action injection (#6)


# License
[MIT](https://choosealicense.com/licenses/mit/)

