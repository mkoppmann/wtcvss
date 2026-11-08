# wtCVSS

`wtcvss` is a simple application written in Elm, that lets you define a score and get a random CVSSv3.1 vector for it. It is mainly meant as a joke project.

## Build setup

```shell
# development shell with Elm (or `direnv allow`)
nix develop

# serve at localhost:8000
elm reactor

# build for production into result/index.html
nix build
```

After changing dependencies, regenerate the pinned sources with
`elm2nix convert > elm-srcs.nix && elm2nix snapshot`.

## Test setup

```shell
# if you don’t have Elm Test installed
npm install -g elm-test

# run tests
elm-test
```

