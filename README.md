# wtCVSS

`wtcvss` is a simple application written in Elm, that lets you define a score and get a random CVSSv3.1 vector for it. It is mainly meant as a joke project.

## Build setup

```shell
# if you don’t have Elm installed
npm install -g elm

# serve at localhost:8000
elm reactor

# build for production
elm make src/Main.elm --optimize --output="wtcvss.html"
```

## Test setup

```shell
# if you don’t have Elm Test installed
npm install -g elm-test

# run tests
elm-test
```

