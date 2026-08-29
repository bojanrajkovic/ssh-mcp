# Changelog

## 0.1.0 (2026-08-29)


### Features

* **conn:** establish, inspect, and tear down control masters ([5259501](https://github.com/bojanrajkovic/ssh-mcp/commit/5259501e0094ec7d1a9e660c9a997eece8854301))
* **exec:** run commands and keep output out of the caller's way ([6de9dfe](https://github.com/bojanrajkovic/ssh-mcp/commit/6de9dfedfe4680ad59e8482c04f806528123b828))
* **jobs:** run commands that outlive the call that started them ([608e246](https://github.com/bojanrajkovic/ssh-mcp/commit/608e246998bda881fae5cd6f513e251f6dc8f37f))
* **server:** expose the tool surface and push job completions ([b3a2d4f](https://github.com/bojanrajkovic/ssh-mcp/commit/b3a2d4f23fbbbb948089d555fad4ea76f27ba69e))
* **server:** log job-watcher outcomes at info level ([d0e617b](https://github.com/bojanrajkovic/ssh-mcp/commit/d0e617b6c2871faf214da759de53e6a63dd67dd0))
* **sshcfg:** derive connection identifiers and own the ssh_config ([080f4f4](https://github.com/bojanrajkovic/ssh-mcp/commit/080f4f49402e221211b6bed85d59cbe40328865e))
* **xfer:** copy files and read or write their contents ([1fbae3d](https://github.com/bojanrajkovic/ssh-mcp/commit/1fbae3d200ca52559bfe41a3572f3bfdb6d1e800))


### Bug Fixes

* **ci:** cap the macOS notarization timeout at 20m ([e5327da](https://github.com/bojanrajkovic/ssh-mcp/commit/e5327dac1152dc84f5a0eaf05567eb8a37b51944))
* **sshcfg:** reject a config directory too deep for control sockets ([3f67dee](https://github.com/bojanrajkovic/ssh-mcp/commit/3f67deecbc47865c08c8bc757f429fc224474358))
* **sshtest:** detach the job wrapper on bash as well as busybox ([140fefb](https://github.com/bojanrajkovic/ssh-mcp/commit/140fefb7e706381a4d36ce383693579bd8bb52fc))
* **sshtest:** keep ControlPath under the macOS socket length limit ([6a64b6d](https://github.com/bojanrajkovic/ssh-mcp/commit/6a64b6d4c3fad3aa31b389ddc081b091fcbacf48))
* **sshtest:** read the container id from stdout only ([a207605](https://github.com/bojanrajkovic/ssh-mcp/commit/a2076051bfa5a819a492b6df68f43d997fb79295))
