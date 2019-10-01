module Cvss exposing (..)

import Random
import Random.Extra exposing (andMap)
import Round exposing (ceilingNum)



-- CONSTANTS


{-| The minimal precision when a vector score is seen as valid.
The value is needed, because there are some ranges where there are no matching vectors.
-}
minPrecision =
    1.0


type alias Vector =
    { av : AttackVector
    , ac : AttackComplexity
    , pr : PrivilegesRequired
    , ui : UserInteraction
    , s : Scope
    , c : ConfidentialityImpact
    , i : IntegrityImpact
    , a : AvailabilityImpact
    }


type AttackVector
    = AvNetwork
    | AvAdjacentNetwork
    | AvLocal
    | AvPhysical


type AttackComplexity
    = AcLow
    | AcHigh


type PrivilegesRequired
    = PrNone
    | PrLow
    | PrHigh


type UserInteraction
    = UiNone
    | UiRequired


type Scope
    = SUnchanged
    | SChanged


type ConfidentialityImpact
    = CNone
    | CLow
    | CHigh


type IntegrityImpact
    = INone
    | ILow
    | IHigh


type AvailabilityImpact
    = ANone
    | ALow
    | AHigh


type Severity
    = SLow
    | SMedium
    | SHigh
    | SCritical
    | SNone



-- CVSSV3 CALCULATION


{-| “Round up” as specified here:
<https://www.first.org/cvss/v3.1/specification-document#CVSS-v3-1-Equations>

    roundUp 4.02 == 4.1

    roundUp 4.0 == 4.0

-}
roundUp : Float -> Float
roundUp value =
    ceilingNum 1 value


calculateBaseScore : Vector -> Float
calculateBaseScore vector =
    let
        impact =
            impactSubScore vector

        exploitability =
            exploitabilitySubScore vector
    in
    if impact <= 0 then
        0.0

    else
        case vector.s of
            SUnchanged ->
                roundUp <| Basics.min (impact + exploitability) 10.0

            SChanged ->
                roundUp <| Basics.min (1.08 * (impact + exploitability)) 10.0


impactSubScore : Vector -> Float
impactSubScore vector =
    let
        iscBase =
            impactSubScoreBase vector
    in
    case vector.s of
        SUnchanged ->
            6.42 * iscBase

        SChanged ->
            (7.52 * (iscBase - 0.029)) - (3.25 * (iscBase - 0.02) ^ 15)


impactSubScoreBase : Vector -> Float
impactSubScoreBase vector =
    let
        impactConf =
            1 - toFloatConfidentialityImpact vector.c

        impactInteg =
            1 - toFloatIntegrityImpact vector.i

        impactAvail =
            1 - toFloatAvailabilityImpact vector.a
    in
    1 - (impactConf * impactInteg * impactAvail)


exploitabilitySubScore : Vector -> Float
exploitabilitySubScore vector =
    let
        av =
            toFloatAttackVector vector.av

        ac =
            toFloatAttackComplexity vector.ac

        pr =
            toFloatPrivilegesRequired vector.s vector.pr

        ui =
            toFloatUserInteraction vector.ui
    in
    8.22 * av * ac * pr * ui



-- toFloat


toFloatAttackVector : AttackVector -> Float
toFloatAttackVector av =
    case av of
        AvNetwork ->
            0.85

        AvAdjacentNetwork ->
            0.62

        AvLocal ->
            0.55

        AvPhysical ->
            0.2


toFloatAttackComplexity : AttackComplexity -> Float
toFloatAttackComplexity ac =
    case ac of
        AcLow ->
            0.77

        AcHigh ->
            0.44


toFloatPrivilegesRequired : Scope -> PrivilegesRequired -> Float
toFloatPrivilegesRequired s pr =
    case s of
        SUnchanged ->
            case pr of
                PrNone ->
                    0.85

                PrLow ->
                    0.62

                PrHigh ->
                    0.27

        SChanged ->
            case pr of
                PrNone ->
                    0.85

                PrLow ->
                    0.68

                PrHigh ->
                    0.5


toFloatUserInteraction : UserInteraction -> Float
toFloatUserInteraction ui =
    case ui of
        UiNone ->
            0.85

        UiRequired ->
            0.62


toFloatConfidentialityImpact : ConfidentialityImpact -> Float
toFloatConfidentialityImpact c =
    case c of
        CHigh ->
            0.56

        CLow ->
            0.22

        CNone ->
            0


toFloatIntegrityImpact : IntegrityImpact -> Float
toFloatIntegrityImpact i =
    case i of
        IHigh ->
            0.56

        ILow ->
            0.22

        INone ->
            0.0


toFloatAvailabilityImpact : AvailabilityImpact -> Float
toFloatAvailabilityImpact a =
    case a of
        AHigh ->
            0.56

        ALow ->
            0.22

        ANone ->
            0.0



-- toString


toStringVector : Vector -> String
toStringVector vector =
    "CVSS:3.1"
        ++ "/"
        ++ toStringAttackVector vector.av
        ++ "/"
        ++ toStringAttackComplexity vector.ac
        ++ "/"
        ++ toStringPrivilegesRequired vector.pr
        ++ "/"
        ++ toStringUserInteraction vector.ui
        ++ "/"
        ++ toStringScope vector.s
        ++ "/"
        ++ toStringConfidentialityImpact vector.c
        ++ "/"
        ++ toStringIntegrityImpact vector.i
        ++ "/"
        ++ toStringAvailabilityImpact vector.a


toStringAttackVector : AttackVector -> String
toStringAttackVector av =
    case av of
        AvNetwork ->
            "AV:N"

        AvAdjacentNetwork ->
            "AV:A"

        AvLocal ->
            "AV:L"

        AvPhysical ->
            "AV:P"


toStringAttackComplexity : AttackComplexity -> String
toStringAttackComplexity ac =
    case ac of
        AcLow ->
            "AC:L"

        AcHigh ->
            "AC:H"


toStringPrivilegesRequired : PrivilegesRequired -> String
toStringPrivilegesRequired pr =
    case pr of
        PrNone ->
            "PR:N"

        PrLow ->
            "PR:L"

        PrHigh ->
            "PR:H"


toStringUserInteraction : UserInteraction -> String
toStringUserInteraction ui =
    case ui of
        UiNone ->
            "UI:N"

        UiRequired ->
            "UI:R"


toStringScope : Scope -> String
toStringScope s =
    case s of
        SUnchanged ->
            "S:U"

        SChanged ->
            "S:C"


toStringConfidentialityImpact : ConfidentialityImpact -> String
toStringConfidentialityImpact c =
    case c of
        CNone ->
            "C:N"

        CLow ->
            "C:L"

        CHigh ->
            "C:H"


toStringIntegrityImpact : IntegrityImpact -> String
toStringIntegrityImpact i =
    case i of
        INone ->
            "I:N"

        ILow ->
            "I:L"

        IHigh ->
            "I:H"


toStringAvailabilityImpact : AvailabilityImpact -> String
toStringAvailabilityImpact a =
    case a of
        ANone ->
            "A:N"

        ALow ->
            "A:L"

        AHigh ->
            "A:H"


toStringSeverity : Severity -> String
toStringSeverity severity =
    case severity of
        SNone ->
            "None"

        SLow ->
            "Low"

        SMedium ->
            "Medium"

        SHigh ->
            "High"

        SCritical ->
            "Critical"



-- Random generators


getMatchingVector : Float -> Float -> Random.Generator Vector
getMatchingVector maxPrecision score =
    let
        minValue =
            score - minPrecision

        maxValue =
            score + maxPrecision

        isInRange calculatedScore =
            minValue <= calculatedScore && calculatedScore <= maxValue
    in
    Random.Extra.filter (\vector -> isInRange <| calculateBaseScore vector) randomVector


randomVector : Random.Generator Vector
randomVector =
    Random.map Vector randomAttackVector
        |> andMap randomAttackComplexity
        |> andMap randomPrivilegesRequired
        |> andMap randomUserInteraction
        |> andMap randomScope
        |> andMap randomConfidentialityImpact
        |> andMap randomIntegrityImpact
        |> andMap randomAvailabilityImpact


randomAttackVector : Random.Generator AttackVector
randomAttackVector =
    Random.uniform AvNetwork [ AvAdjacentNetwork, AvLocal, AvPhysical ]


randomAttackComplexity : Random.Generator AttackComplexity
randomAttackComplexity =
    Random.uniform AcLow [ AcHigh ]


randomPrivilegesRequired : Random.Generator PrivilegesRequired
randomPrivilegesRequired =
    Random.uniform PrNone [ PrLow, PrHigh ]


randomUserInteraction : Random.Generator UserInteraction
randomUserInteraction =
    Random.uniform UiNone [ UiRequired ]


randomScope : Random.Generator Scope
randomScope =
    Random.uniform SUnchanged [ SChanged ]


randomConfidentialityImpact : Random.Generator ConfidentialityImpact
randomConfidentialityImpact =
    Random.uniform CNone [ CLow, CHigh ]


randomIntegrityImpact : Random.Generator IntegrityImpact
randomIntegrityImpact =
    Random.uniform INone [ ILow, IHigh ]


randomAvailabilityImpact : Random.Generator AvailabilityImpact
randomAvailabilityImpact =
    Random.uniform ANone [ ALow, AHigh ]


toSeverityVector : Vector -> Severity
toSeverityVector vector =
    let
        score =
            calculateBaseScore vector
    in
    if 0.1 <= score && score <= 3.9 then
        SLow

    else if 4.0 <= score && score <= 6.9 then
        SMedium

    else if 7.0 <= score && score <= 8.9 then
        SHigh

    else if 9.0 <= score && score <= 10.0 then
        SCritical

    else
        SNone


toColorSeverity : Severity -> String
toColorSeverity severity =
    case severity of
        SNone ->
            "#000000"

        SLow ->
            "#ffff00"

        SMedium ->
            "#ff6600"

        SHigh ->
            "#ff0000"

        SCritical ->
            "#660000"
