module Main exposing (Model, Msg(..), init, main, update, view)

import Browser
import Cvss exposing (..)
import Dict exposing (Dict)
import Html exposing (Attribute, Html, a, button, code, div, input, li, small, text, ul)
import Html.Attributes exposing (..)
import Html.Events exposing (onClick, onInput)
import Maybe.Extra exposing (values)
import Random exposing (generate)



-- CONSTANTS


cvssv3MinimumScore =
    0.0


cvssv3MaximumScore =
    10.0


firstOrgCvssPrefix =
    "https://www.first.org/cvss/calculator/3.1#"



-- MAIN


main =
    Browser.element
        { init = init
        , update = update
        , subscriptions = subscriptions
        , view = view
        }



-- MODEL


type alias Model =
    { precision : Float
    , score : Float
    , vector : Vector
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { precision = minPrecision
      , score = cvssv3MinimumScore
      , vector = initVector
      }
    , Cmd.none
    )


initVector : Vector
initVector =
    Vector AvNetwork AcLow PrNone UiNone SUnchanged CNone INone ANone



-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions model =
    Sub.none



-- UPDATE


type Msg
    = ChangePrecision String
    | ChangeScore String
    | ChangeVector Vector
    | ChangeScoreAndVector Vector
    | CalculateVectorAgain
    | NewRandomVector


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        ChangePrecision newPrecision ->
            let
                floatPrecision =
                    Maybe.withDefault 1 <| String.toFloat newPrecision
            in
            ( { model
                | precision = floatPrecision
              }
            , newRandomVectorWithScore floatPrecision model.score
            )

        ChangeScore newScore ->
            let
                floatScore =
                    Maybe.withDefault 0.0 <| String.toFloat newScore
            in
            ( { model
                | score = floatScore
              }
            , newRandomVectorWithScore model.precision floatScore
            )

        ChangeVector newVector ->
            ( { model
                | vector = newVector
              }
            , Cmd.none
            )

        ChangeScoreAndVector newVector ->
            ( { model
                | score = calculateBaseScore newVector
                , vector = newVector
              }
            , Cmd.none
            )

        CalculateVectorAgain ->
            ( model
            , newRandomVectorWithScore model.precision model.score
            )

        NewRandomVector ->
            ( model
            , newRandomVector
            )



-- VIEW


view : Model -> Html Msg
view model =
    div []
        [ div []
            [ div []
                [ text "Precision"
                , precisionInput model.precision
                ]
            , div []
                [ text "Score"
                , scoreInput "range" model.score
                , scoreInput "number" model.score
                ]
            , button [ onClick CalculateVectorAgain ] [ text "Generate another vector" ]
            , button [ onClick NewRandomVector ] [ text "Get random vector" ]
            ]
        , div [] <| viewVector model.vector
        , small []
            [ a [ href "https://github.com/mkoppmann/wtcvss" ] [ text "Source Code" ]
            ]
        ]


precisionInput : Float -> Html Msg
precisionInput precision =
    input
        [ type_ "number"
        , Html.Attributes.min <| String.fromFloat minPrecision
        , Html.Attributes.step "0.1"
        , value <| String.fromFloat precision
        , onInput ChangePrecision
        ]
        []


scoreInput : String -> Float -> Html Msg
scoreInput inputType score =
    input
        [ type_ inputType
        , Html.Attributes.min <| String.fromFloat cvssv3MinimumScore
        , Html.Attributes.max <| String.fromFloat cvssv3MaximumScore
        , Html.Attributes.step "0.1"
        , value <| String.fromFloat score
        , onInput ChangeScore
        ]
        []


viewVector : Vector -> List (Html Msg)
viewVector vector =
    let
        sVector =
            toStringVector vector

        sVectorUrl =
            firstOrgCvssPrefix ++ sVector

        sVectorScore =
            String.fromFloat (calculateBaseScore vector)

        aTag =
            a [ href sVectorUrl ] <| [ code [] [ text sVector ] ]
    in
    [ aTag
    , text <| " – " ++ sVectorScore
    ]



-- Random


newRandomVectorWithScore : Float -> Float -> Cmd Msg
newRandomVectorWithScore maxPrecision score =
    Random.generate ChangeVector <| getMatchingVector maxPrecision score


newRandomVector : Cmd Msg
newRandomVector =
    Random.generate ChangeScoreAndVector randomVector
