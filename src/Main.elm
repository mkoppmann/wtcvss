module Main exposing (Model, Msg(..), init, main, update, view)

import Browser
import Browser.Dom exposing (Viewport, getViewport)
import Browser.Events exposing (onResize)
import Cvss exposing (..)
import Dict exposing (Dict)
import Element exposing (Color, Device, DeviceClass(..), Element, Orientation(..), alignRight, behindContent, centerX, centerY, classifyDevice, column, el, fill, height, layout, link, none, padding, px, rgb, rgb255, rgba, row, shrink, spacing, text, width, wrappedRow)
import Element.Background as Background
import Element.Border as Border
import Element.Font as Font
import Element.Input as Input
import Element.Region as Region
import Html exposing (Html)
import Maybe.Extra exposing (values)
import Random exposing (generate)
import Task



-- CONSTANTS


cvssv3MinimumScore =
    0.0


cvssv3MaximumScore =
    10.0


firstOrgCvssPrefix =
    "https://www.first.org/cvss/calculator/3.1#"


white : Color
white =
    rgb 1 1 1


grey : Color
grey =
    rgb 0.9 0.9 0.9


lightGrey : Color
lightGrey =
    rgb 0.6 0.6 0.6



-- MAIN


main =
    Browser.document
        { init = init
        , update = update
        , subscriptions = subscriptions
        , view = view
        }



-- MODEL


type alias Model =
    { device : Maybe Device
    , precision : Float
    , score : Float
    , vector : Vector
    }


init : () -> ( Model, Cmd Msg )
init _ =
    ( { device = Nothing
      , precision = minPrecision
      , score = cvssv3MinimumScore
      , vector = initVector
      }
    , Task.perform GotViewport getViewport
    )


initVector : Vector
initVector =
    Vector AvNetwork AcLow PrNone UiNone SUnchanged CNone INone ANone



-- SUBSCRIPTIONS


subscriptions : Model -> Sub Msg
subscriptions _ =
    onResize <|
        \width height ->
            DeviceClassified <| classifyDevice { width = width, height = height }



-- UPDATE


type Msg
    = ChangePrecision Float
    | ChangeScore Float
    | ChangeVector Vector
    | ChangeScoreAndVector Vector
    | CalculateVectorAgain
    | DeviceClassified Device
    | GotViewport Viewport
    | NewRandomVector


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        ChangePrecision newPrecision ->
            ( { model | precision = newPrecision }
            , newRandomVectorWithScore newPrecision model.score
            )

        ChangeScore newScore ->
            ( { model | score = newScore }
            , newRandomVectorWithScore model.precision newScore
            )

        ChangeVector newVector ->
            ( { model | vector = newVector }
            , Cmd.none
            )

        ChangeScoreAndVector newVector ->
            ( { model | score = calculateBaseScore newVector, vector = newVector }
            , Cmd.none
            )

        CalculateVectorAgain ->
            ( model
            , newRandomVectorWithScore model.precision model.score
            )

        DeviceClassified device ->
            ( { model | device = Just device }
            , Cmd.none
            )

        GotViewport viewport ->
            ( { model
                | device =
                    Just <|
                        classifyDevice
                            { height = round viewport.viewport.height
                            , width = round viewport.viewport.width
                            }
              }
            , Cmd.none
            )

        NewRandomVector ->
            ( model
            , newRandomVector
            )



-- VIEW


view : Model -> Browser.Document Msg
view model =
    { title = "WTCVSS"
    , body = deviceBody model
    }


deviceBody : Model -> List (Html Msg)
deviceBody model =
    let
        fallback =
            { class = Desktop
            , orientation = Landscape
            }

        device =
            Maybe.withDefault fallback model.device
    in
    case device.class of
        Phone ->
            mobileLayout model

        _ ->
            desktopLayout model


mobileLayout : Model -> List (Html Msg)
mobileLayout model =
    responsiveLayout 0 14 model


desktopLayout : Model -> List (Html Msg)
desktopLayout model =
    responsiveLayout 10 20 model


responsiveLayout : Int -> Int -> Model -> List (Html Msg)
responsiveLayout borderRadius fontSize model =
    [ layout
        [ Background.color grey
        , Region.mainContent
        ]
      <|
        column
            [ Background.color white
            , Border.rounded borderRadius
            , Border.shadow { offset = ( 4, 6 ), size = 1, blur = 8, color = rgba 0 0 0 0.2 }
            , centerX
            , centerY
            , height shrink
            , padding 24
            , spacing 36
            , width shrink
            ]
            [ title
            , precisionInput model.precision
            , scoreInput model.score
            , viewVector fontSize model.vector
            , buttons
            , linkToSourceCode
            ]
    ]


title : Element msg
title =
    el
        [ Font.size 32
        , Font.variant Font.smallCaps
        , Region.heading 1
        ]
        (text "Wtcvss")


linkToSourceCode : Element msg
linkToSourceCode =
    el
        [ alignRight
        , Font.color lightGrey
        , Font.size 14
        , Region.footer
        ]
        (link []
            { url = "https://github.com/mkoppmann/wtcvss"
            , label = text "Source Code"
            }
        )


buttons : Element Msg
buttons =
    wrappedRow
        [ width fill
        , Font.center
        , spacing 10
        ]
        [ vectorButton CalculateVectorAgain "Get another matching vector"
        , vectorButton NewRandomVector "Get vector with random score"
        ]


vectorButton : Msg -> String -> Element Msg
vectorButton message labelText =
    Input.button
        [ width shrink
        , Background.color grey
        , padding 10
        , Border.rounded 5
        ]
        { onPress = Just message
        , label = text labelText
        }


precisionInput : Float -> Element Msg
precisionInput precision =
    inputSlider ChangePrecision "Precision: " minPrecision precision


scoreInput : Float -> Element Msg
scoreInput score =
    inputSlider ChangeScore "Target score: " cvssv3MinimumScore score


inputSlider : (Float -> Msg) -> String -> Float -> Float -> Element Msg
inputSlider message label minimum value =
    row [ width fill ]
        [ Input.slider
            [ height (px 30)
            , behindContent
                (el
                    [ width fill
                    , height (px 2)
                    , centerY
                    , Background.color grey
                    ]
                    none
                )
            ]
            { onChange = message
            , label = Input.labelAbove [] (text <| label ++ String.fromFloat value)
            , min = minimum
            , max = cvssv3MaximumScore
            , step = Just 0.1
            , value = value
            , thumb = Input.defaultThumb
            }
        ]


viewVector : Int -> Vector -> Element msg
viewVector size vector =
    let
        sVector =
            toStringVector vector

        sVectorUrl =
            firstOrgCvssPrefix ++ sVector

        sVectorScore =
            String.fromFloat (calculateBaseScore vector)

        linkedVector =
            el
                [ Background.color <| toColorSeverity <| toSeverityVector vector
                , Border.innerShadow { offset = ( 0, 2 ), size = 0, blur = 4, color = rgba 0 0 0 0.2 }
                , Border.rounded 5
                , Font.color white
                , Font.size size
                , padding 10
                ]
                (link
                    [ Font.family [ Font.monospace ] ]
                    { url = sVectorUrl
                    , label = text sVector
                    }
                )
    in
    column [ spacing 10 ]
        [ text <|
            "Vector score: "
                ++ sVectorScore
                ++ " ("
                ++ (toStringSeverity <| toSeverityVector vector)
                ++ ")"
        , linkedVector
        ]


toColorSeverity : Severity -> Color
toColorSeverity severity =
    case severity of
        SNone ->
            rgb255 83 170 51

        SLow ->
            rgb255 255 203 13

        SMedium ->
            rgb255 249 160 9

        SHigh ->
            rgb255 223 61 3

        SCritical ->
            rgb255 204 5 0



-- Random


newRandomVectorWithScore : Float -> Float -> Cmd Msg
newRandomVectorWithScore maxPrecision score =
    Random.generate ChangeVector <| getMatchingVector maxPrecision score


newRandomVector : Cmd Msg
newRandomVector =
    Random.generate ChangeScoreAndVector randomVector
