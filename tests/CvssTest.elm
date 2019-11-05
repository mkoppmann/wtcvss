module CvssTest exposing (..)

import Cvss exposing (..)
import Expect exposing (Expectation)
import Test exposing (..)



-- TESTS


cvtest =
    describe "The CVSS module"
        [ describe "CVSS base score calculation"
            [ test "testBaseVector1 has correct score" <|
                \_ ->
                    testBaseVector 8.4 baseVectorValue1
            , test "testBaseVector2 has correct score" <|
                \_ ->
                    testBaseVector 7.5 baseVectorValue2
            , test "testBaseVector3 has correct score" <|
                \_ ->
                    testBaseVector 8.1 baseVectorValue3
            , test "testBaseVector4 has correct score" <|
                \_ ->
                    testBaseVector 5.7 baseVectorValue4
            , test "testBaseVector5 has correct score" <|
                \_ ->
                    testBaseVector 7.6 baseVectorValue5
            , test "testBaseVector6 has correct score" <|
                \_ ->
                    testBaseVector 5.9 baseVectorValue6
            , test "testBaseVector7 has correct score" <|
                \_ ->
                    testBaseVector 5.5 baseVectorValue7
            , test "testBaseVector8 has correct score" <|
                \_ ->
                    testBaseVector 7.6 baseVectorValue8
            , test "testBaseVector9 has correct score" <|
                \_ ->
                    testBaseVector 0.0 baseVectorValue9
            , test "testBaseVector10 has correct score" <|
                \_ ->
                    testBaseVector 10.0 baseVectorValue10
            ]
        , describe "CVSS temporal score calculation"
            [ test "testTemporalVectorValue1ForBase1 has correct score" <|
                \_ ->
                    testTemporalVector 8.4 temporalVectorValue1ForBase1
            , test "testTemporalVectorValue2ForBase1 has correct score" <|
                \_ ->
                    testTemporalVector 6.8 temporalVectorValue2ForBase1
            , test "testTemporalVectorValue3ForBase1 has correct score" <|
                \_ ->
                    testTemporalVector 7.6 temporalVectorValue3ForBase1
            , test "testTemporalVectorValue1ForBase2 has correct score" <|
                \_ ->
                    testTemporalVector 6.8 temporalVectorValue1ForBase2
            , test "testTemporalVectorValue2ForBase2 has correct score" <|
                \_ ->
                    testTemporalVector 6.5 temporalVectorValue2ForBase2
            , test "testTemporalVectorValue3ForBase2 has correct score" <|
                \_ ->
                    testTemporalVector 6.9 temporalVectorValue3ForBase2
            ]
        ]



-- CONSTANTS


baseVectorValue1 : BaseVectorValue
baseVectorValue1 =
    BaseVectorValue AvNetwork AcLow PrHigh UiRequired SChanged CHigh IHigh AHigh


temporalVectorValue1ForBase1 : TemporalVectorValue
temporalVectorValue1ForBase1 =
    TemporalVectorValue baseVectorValue1 ENotDefined RlNotDefined RcNotDefined


temporalVectorValue2ForBase1 : TemporalVectorValue
temporalVectorValue2ForBase1 =
    TemporalVectorValue baseVectorValue1 EUnproven RlTemporaryFix RcUnknown


temporalVectorValue3ForBase1 : TemporalVectorValue
temporalVectorValue3ForBase1 =
    TemporalVectorValue baseVectorValue1 EFunctional RlWorkaround RcReasonable


baseVectorValue2 : BaseVectorValue
baseVectorValue2 =
    BaseVectorValue AvNetwork AcLow PrHigh UiRequired SChanged CLow IHigh ALow


temporalVectorValue1ForBase2 : TemporalVectorValue
temporalVectorValue1ForBase2 =
    TemporalVectorValue baseVectorValue2 EFunctional RlWorkaround RcReasonable


temporalVectorValue2ForBase2 : TemporalVectorValue
temporalVectorValue2ForBase2 =
    TemporalVectorValue baseVectorValue2 EProofOfConcept RlUnavailable RcUnknown


temporalVectorValue3ForBase2 : TemporalVectorValue
temporalVectorValue3ForBase2 =
    TemporalVectorValue baseVectorValue2 EHigh RlOfficialFix RcReasonable


baseVectorValue3 : BaseVectorValue
baseVectorValue3 =
    BaseVectorValue AvLocal AcLow PrLow UiRequired SChanged CHigh ILow AHigh


baseVectorValue4 : BaseVectorValue
baseVectorValue4 =
    BaseVectorValue AvAdjacentNetwork AcLow PrLow UiNone SUnchanged CHigh INone ANone


baseVectorValue5 : BaseVectorValue
baseVectorValue5 =
    BaseVectorValue AvLocal AcHigh PrNone UiRequired SChanged CHigh ILow AHigh


baseVectorValue6 : BaseVectorValue
baseVectorValue6 =
    BaseVectorValue AvNetwork AcHigh PrNone UiRequired SUnchanged CNone ILow AHigh


baseVectorValue7 : BaseVectorValue
baseVectorValue7 =
    BaseVectorValue AvNetwork AcLow PrHigh UiNone SUnchanged CLow IHigh ANone


baseVectorValue8 : BaseVectorValue
baseVectorValue8 =
    BaseVectorValue AvAdjacentNetwork AcLow PrLow UiNone SChanged CLow IHigh ANone


baseVectorValue9 : BaseVectorValue
baseVectorValue9 =
    BaseVectorValue AvPhysical AcLow PrHigh UiRequired SChanged CNone INone ANone


baseVectorValue10 : BaseVectorValue
baseVectorValue10 =
    BaseVectorValue AvNetwork AcLow PrNone UiNone SChanged CLow IHigh AHigh



-- HELPER


testBaseVector : Float -> BaseVectorValue -> Expectation
testBaseVector score value =
    Expect.within (Expect.Absolute 0.001) score (calculateScore <| BaseVector value)


testTemporalVector : Float -> TemporalVectorValue -> Expectation
testTemporalVector score value =
    Expect.within (Expect.Absolute 0.001) score (calculateScore <| TemporalVector value)
