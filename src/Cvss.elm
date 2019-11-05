module Cvss exposing (AttackComplexity(..), AttackVector(..), AvailabilityImpact(..), BaseVectorValue, ConfidentialityImpact(..), ExploitCodeMaturity(..), IntegrityImpact(..), PrivilegesRequired(..), RemediationLevel(..), ReportConfidence(..), Scope(..), Severity(..), TemporalVectorValue, UserInteraction(..), Vector(..), VectorChoice(..), calculateScore, getMatchingVector, initVector, randomVector, toSeverityVector, toStringSeverity, toStringVector)

import Random
import Random.Extra exposing (andMap, choice)
import Round exposing (ceilingNum)



-- TYPES


type Vector
    = BaseVector BaseVectorValue
    | TemporalVector TemporalVectorValue


type VectorChoice
    = BaseVectorChoice
    | TemporalVectorChoice


type alias BaseVectorValue =
    { av : AttackVector
    , ac : AttackComplexity
    , pr : PrivilegesRequired
    , ui : UserInteraction
    , s : Scope
    , c : ConfidentialityImpact
    , i : IntegrityImpact
    , a : AvailabilityImpact
    }


type alias TemporalVectorValue =
    { base : BaseVectorValue
    , e : ExploitCodeMaturity
    , rl : RemediationLevel
    , rc : ReportConfidence
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


type ExploitCodeMaturity
    = ENotDefined
    | EUnproven
    | EProofOfConcept
    | EFunctional
    | EHigh


type RemediationLevel
    = RlNotDefined
    | RlOfficialFix
    | RlTemporaryFix
    | RlWorkaround
    | RlUnavailable


type ReportConfidence
    = RcNotDefined
    | RcUnknown
    | RcReasonable
    | RcConfirmed


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


calculateScore : Vector -> Float
calculateScore vector =
    case vector of
        BaseVector value ->
            calculateBaseScore value

        TemporalVector value ->
            calculateTemporalScore value


calculateBaseScore : BaseVectorValue -> Float
calculateBaseScore value =
    let
        impact =
            impactSubScore value

        exploitability =
            exploitabilitySubScore value
    in
    if impact <= 0 then
        0.0

    else
        case value.s of
            SUnchanged ->
                roundUp <| Basics.min (impact + exploitability) 10.0

            SChanged ->
                roundUp <| Basics.min (1.08 * (impact + exploitability)) 10.0


impactSubScore : BaseVectorValue -> Float
impactSubScore value =
    let
        iscBase =
            impactSubScoreBase value
    in
    case value.s of
        SUnchanged ->
            6.42 * iscBase

        SChanged ->
            (7.52 * (iscBase - 0.029)) - (3.25 * (iscBase - 0.02) ^ 15)


impactSubScoreBase : BaseVectorValue -> Float
impactSubScoreBase value =
    let
        impactConf =
            1 - toFloatConfidentialityImpact value.c

        impactInteg =
            1 - toFloatIntegrityImpact value.i

        impactAvail =
            1 - toFloatAvailabilityImpact value.a
    in
    1 - (impactConf * impactInteg * impactAvail)


exploitabilitySubScore : BaseVectorValue -> Float
exploitabilitySubScore value =
    let
        av =
            toFloatAttackVector value.av

        ac =
            toFloatAttackComplexity value.ac

        pr =
            toFloatPrivilegesRequired value.s value.pr

        ui =
            toFloatUserInteraction value.ui
    in
    8.22 * av * ac * pr * ui


calculateTemporalScore : TemporalVectorValue -> Float
calculateTemporalScore value =
    let
        baseScore =
            calculateBaseScore value.base

        exploitCodeMaturity =
            toFloatExploitCodeMaturity value.e

        remediationLevel =
            toFloatRemediationLevel value.rl

        reportConfidence =
            toFloatReportConfidence value.rc
    in
    roundUp <| baseScore * exploitCodeMaturity * remediationLevel * reportConfidence



-- TO_FLOAT


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


toFloatExploitCodeMaturity : ExploitCodeMaturity -> Float
toFloatExploitCodeMaturity em =
    case em of
        ENotDefined ->
            1.0

        EUnproven ->
            0.91

        EProofOfConcept ->
            0.94

        EFunctional ->
            0.97

        EHigh ->
            1


toFloatRemediationLevel : RemediationLevel -> Float
toFloatRemediationLevel rl =
    case rl of
        RlNotDefined ->
            1.0

        RlOfficialFix ->
            0.95

        RlTemporaryFix ->
            0.96

        RlWorkaround ->
            0.97

        RlUnavailable ->
            1.0


toFloatReportConfidence : ReportConfidence -> Float
toFloatReportConfidence rc =
    case rc of
        RcNotDefined ->
            1.0

        RcUnknown ->
            0.92

        RcReasonable ->
            0.96

        RcConfirmed ->
            1.0



-- TO_STRING


toStringVector : Vector -> String
toStringVector vector =
    case vector of
        BaseVector value ->
            toStringBaseVector value

        TemporalVector value ->
            toStringTemporalVector value


toStringTemporalVector : TemporalVectorValue -> String
toStringTemporalVector value =
    String.dropRight 1 <|
        toStringBaseVector value.base
            ++ "/"
            ++ toStringExploitCodeMaturity value.e
            ++ toStringRemediationLevel value.rl
            ++ toStringReportConfidence value.rc


toStringBaseVector : BaseVectorValue -> String
toStringBaseVector value =
    String.dropRight 1 <|
        "CVSS:3.1/"
            ++ toStringAttackVector value.av
            ++ toStringAttackComplexity value.ac
            ++ toStringPrivilegesRequired value.pr
            ++ toStringUserInteraction value.ui
            ++ toStringScope value.s
            ++ toStringConfidentialityImpact value.c
            ++ toStringIntegrityImpact value.i
            ++ toStringAvailabilityImpact value.a


toStringAttackVector : AttackVector -> String
toStringAttackVector av =
    case av of
        AvNetwork ->
            "AV:N/"

        AvAdjacentNetwork ->
            "AV:A/"

        AvLocal ->
            "AV:L/"

        AvPhysical ->
            "AV:P/"


toStringAttackComplexity : AttackComplexity -> String
toStringAttackComplexity ac =
    case ac of
        AcLow ->
            "AC:L/"

        AcHigh ->
            "AC:H/"


toStringPrivilegesRequired : PrivilegesRequired -> String
toStringPrivilegesRequired pr =
    case pr of
        PrNone ->
            "PR:N/"

        PrLow ->
            "PR:L/"

        PrHigh ->
            "PR:H/"


toStringUserInteraction : UserInteraction -> String
toStringUserInteraction ui =
    case ui of
        UiNone ->
            "UI:N/"

        UiRequired ->
            "UI:R/"


toStringScope : Scope -> String
toStringScope s =
    case s of
        SUnchanged ->
            "S:U/"

        SChanged ->
            "S:C/"


toStringConfidentialityImpact : ConfidentialityImpact -> String
toStringConfidentialityImpact c =
    case c of
        CNone ->
            "C:N/"

        CLow ->
            "C:L/"

        CHigh ->
            "C:H/"


toStringIntegrityImpact : IntegrityImpact -> String
toStringIntegrityImpact i =
    case i of
        INone ->
            "I:N/"

        ILow ->
            "I:L/"

        IHigh ->
            "I:H/"


toStringAvailabilityImpact : AvailabilityImpact -> String
toStringAvailabilityImpact a =
    case a of
        ANone ->
            "A:N/"

        ALow ->
            "A:L/"

        AHigh ->
            "A:H/"


toStringExploitCodeMaturity : ExploitCodeMaturity -> String
toStringExploitCodeMaturity em =
    case em of
        ENotDefined ->
            ""

        EUnproven ->
            "E:U/"

        EProofOfConcept ->
            "E:F/"

        EFunctional ->
            "E:P/"

        EHigh ->
            "E:H/"


toStringRemediationLevel : RemediationLevel -> String
toStringRemediationLevel rl =
    case rl of
        RlNotDefined ->
            ""

        RlOfficialFix ->
            "RL:O/"

        RlTemporaryFix ->
            "RL:T/"

        RlWorkaround ->
            "RL:W/"

        RlUnavailable ->
            "RL:U/"


toStringReportConfidence : ReportConfidence -> String
toStringReportConfidence rc =
    case rc of
        RcNotDefined ->
            ""

        RcUnknown ->
            "RC:U/"

        RcReasonable ->
            "RC:R/"

        RcConfirmed ->
            "RC:C/"


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



-- RANDOM


getMatchingVector : VectorChoice -> Float -> Float -> Float -> Random.Generator Vector
getMatchingVector choice minPrecision maxPrecision score =
    let
        minValue =
            score - minPrecision

        maxValue =
            score + maxPrecision

        isInRange calculatedScore =
            minValue <= calculatedScore && calculatedScore <= maxValue
    in
    case choice of
        BaseVectorChoice ->
            Random.Extra.filter (\vector -> isInRange <| calculateScore vector) randomBaseVector

        TemporalVectorChoice ->
            Random.Extra.filter (\vector -> isInRange <| calculateScore vector) randomTemporalVector


randomVector : VectorChoice -> Random.Generator Vector
randomVector choice =
    case choice of
        BaseVectorChoice ->
            randomBaseVector

        TemporalVectorChoice ->
            randomTemporalVector


randomTemporalVector : Random.Generator Vector
randomTemporalVector =
    let
        baseVectorValue =
            Random.map extractBaseVectorValue randomBaseVector
    in
    Random.map TemporalVector
        (Random.map TemporalVectorValue baseVectorValue
            |> andMap randomExploitCodeMaturity
            |> andMap randomRemediationLevel
            |> andMap randomReportConfidence
        )


randomBaseVector : Random.Generator Vector
randomBaseVector =
    Random.map BaseVector
        (Random.map BaseVectorValue randomAttackVector
            |> andMap randomAttackComplexity
            |> andMap randomPrivilegesRequired
            |> andMap randomUserInteraction
            |> andMap randomScope
            |> andMap randomConfidentialityImpact
            |> andMap randomIntegrityImpact
            |> andMap randomAvailabilityImpact
        )


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


randomExploitCodeMaturity : Random.Generator ExploitCodeMaturity
randomExploitCodeMaturity =
    Random.uniform ENotDefined [ EUnproven, EProofOfConcept, EFunctional, EHigh ]


randomRemediationLevel : Random.Generator RemediationLevel
randomRemediationLevel =
    Random.uniform RlNotDefined [ RlOfficialFix, RlTemporaryFix, RlWorkaround, RlUnavailable ]


randomReportConfidence : Random.Generator ReportConfidence
randomReportConfidence =
    Random.uniform RcNotDefined [ RcUnknown, RcReasonable, RcConfirmed ]



-- SEVERITY


toSeverityVector : Vector -> Severity
toSeverityVector vector =
    let
        score =
            calculateScore vector
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



-- HELPER


initVector : Vector
initVector =
    BaseVector (BaseVectorValue AvNetwork AcLow PrNone UiNone SUnchanged CNone INone ANone)


extractBaseVectorValue : Vector -> BaseVectorValue
extractBaseVectorValue vector =
    case vector of
        BaseVector value ->
            value

        TemporalVector value ->
            value.base


extractTemporalVectorValue : Vector -> Maybe TemporalVectorValue
extractTemporalVectorValue vector =
    case vector of
        BaseVector _ ->
            Nothing

        TemporalVector value ->
            Just value
