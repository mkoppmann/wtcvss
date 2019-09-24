module CvssTest exposing (..)

import Cvss exposing (..)
import Expect exposing (Expectation)
import Test exposing (..)


cvtest =
    describe "The CVSS module"
        [ describe "CVSS calculation"
            [ test "testVector1 has correct score" <|
                \_ ->
                    let
                        testVector1 =
                            Vector AvNetwork AcLow PrHigh UiRequired SChanged CHigh IHigh AHigh

                        score1 =
                            8.4
                    in
                    Expect.within (Expect.Absolute 0.001) score1 (calculateBaseScore testVector1)
            , test "testVector2 has correct score" <|
                \_ ->
                    let
                        testVector2 =
                            Vector AvNetwork AcLow PrHigh UiRequired SChanged CLow IHigh ALow

                        score2 =
                            7.5
                    in
                    Expect.within (Expect.Absolute 0.001) score2 (calculateBaseScore testVector2)
            , test "testVector3 has correct score" <|
                \_ ->
                    let
                        testVector3 =
                            Vector AvLocal AcLow PrLow UiRequired SChanged CHigh ILow AHigh

                        score3 =
                            8.1
                    in
                    Expect.within (Expect.Absolute 0.001) score3 (calculateBaseScore testVector3)
            , test "testVector4 has correct score" <|
                \_ ->
                    let
                        testVector4 =
                            Vector AvAdjacentNetwork AcLow PrLow UiNone SUnchanged CHigh INone ANone

                        score4 =
                            5.7
                    in
                    Expect.within (Expect.Absolute 0.001) score4 (calculateBaseScore testVector4)
            , test "testVector5 has correct score" <|
                \_ ->
                    let
                        testVector5 =
                            Vector AvLocal AcHigh PrNone UiRequired SChanged CHigh ILow AHigh

                        score5 =
                            7.6
                    in
                    Expect.within (Expect.Absolute 0.001) score5 (calculateBaseScore testVector5)
            , test "testVector6 has correct score" <|
                \_ ->
                    let
                        testVector6 =
                            Vector AvNetwork AcHigh PrNone UiRequired SUnchanged CNone ILow AHigh

                        score6 =
                            5.9
                    in
                    Expect.within (Expect.Absolute 0.001) score6 (calculateBaseScore testVector6)
            , test "testVector7 has correct score" <|
                \_ ->
                    let
                        testVector7 =
                            Vector AvNetwork AcLow PrHigh UiNone SUnchanged CLow IHigh ANone

                        score7 =
                            5.5
                    in
                    Expect.within (Expect.Absolute 0.001) score7 (calculateBaseScore testVector7)
            , test "testVector8 has correct score" <|
                \_ ->
                    let
                        testVector8 =
                            Vector AvAdjacentNetwork AcLow PrLow UiNone SChanged CLow IHigh ANone

                        score8 =
                            7.6
                    in
                    Expect.within (Expect.Absolute 0.001) score8 (calculateBaseScore testVector8)
            , test "testVector9 has correct score" <|
                \_ ->
                    let
                        testVector9 =
                            Vector AvPhysical AcLow PrHigh UiRequired SChanged CNone INone ANone

                        score9 =
                            0.0
                    in
                    Expect.within (Expect.Absolute 0.001) score9 (calculateBaseScore testVector9)
            , test "testVector10 has correct score" <|
                \_ ->
                    let
                        testVector10 =
                            Vector AvNetwork AcLow PrNone UiNone SChanged CLow IHigh AHigh

                        score10 =
                            10.0
                    in
                    Expect.within (Expect.Absolute 0.001) score10 (calculateBaseScore testVector10)
            ]
        ]
