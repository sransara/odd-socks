# Odd socks
Implementation of [SOCKS 5 protocol](https://www.ietf.org/rfc/rfc1928.txt) in Go.

## Usage
``` sh
> go get github.com/sransara/oddsocks
> oddsocks -h
Usage of oddsocks:
    -laddr string
        Specify host:port to listen for incoming SOCKS connections (default ":0")
```
## Features
- [X] No configuration (rulesets, username/password etc.) bells and whistles
- [X] Make your own customization by injecting appropriate state handler or action into the state machine
- [X] No external dependencies
- [ ] Auth Methods
    - [X] No authentication
    - [ ] Username/password
    - [ ] GSSAPI
- [X] Address Type
    - [X] IPv4
    - [X] IPv6
    - [X] Domain name
- [X] Commands
    - [X] Connect : production ready
    - [X] Bind : see Issues section
    - [X] UDP associate : see Issues section
        - [X] Fragment support : assuming single fragment

## Issues that need support with suggestions and PRs
- Need functional testing for BIND command ([#1][i1])
- Need functional testing for UDP ASSOC command ([#2][i2])
- Automated integration test suite ([#3][i3])
- Add UDP Fragment support ([#4][i4])
- Implement socks relay ([#5][i5])
- Better strategy for state handler and action injection ([#6][i6])

## License
[MIT](https://choosealicense.com/licenses/mit/)

[i1]: https://github.com/sransara/odd-socks/issues/1
[i2]: https://github.com/sransara/odd-socks/issues/2
[i3]: https://github.com/sransara/odd-socks/issues/3
[i4]: https://github.com/sransara/odd-socks/issues/4
[i5]: https://github.com/sransara/odd-socks/issues/5
[i6]: https://github.com/sransara/odd-socks/issues/6

