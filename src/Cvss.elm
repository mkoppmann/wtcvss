module Cvss exposing (AttackComplexity(..), AttackVector(..), AvailabilityImpact(..), AvailabilityRequirement(..), BaseVectorValue, ConfidentialityImpact(..), ConfidentialityRequirement(..), EnvironmentalVectorValue, ExploitCodeMaturity(..), IntegrityImpact(..), IntegrityRequirement(..), ModifiedAttackComplexity(..), ModifiedAttackVector(..), ModifiedAvailabilityImpact(..), ModifiedConfidentialityImpact(..), ModifiedIntegrityImpact(..), ModifiedPrivilegesRequired(..), ModifiedScope(..), ModifiedUserInteraction(..), PrivilegesRequired(..), RemediationLevel(..), ReportConfidence(..), Scope(..), Severity(..), TemporalVectorValue, UserInteraction(..), Vector(..), VectorChoice(..), calculateScore, getMatchingVector, initVector, randomVector, toSeverityVector, toStringSeverity, toStringVector)

import Random
import Random.Extra exposing (andMap)
import Round exposing (ceilingNum)



-- TYPES


type Vector
    = BaseVector BaseVectorValue
    | TemporalVector TemporalVectorValue
    | EnvironmentalVector EnvironmentalVectorValue


type VectorChoice
    = BaseVectorChoice
    | TemporalVectorChoice
    | EnvironmentalVectorChoice


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


type alias EnvironmentalVectorValue =
    { temp : TemporalVectorValue
    , cr : ConfidentialityRequirement
    , ir : IntegrityRequirement
    , ar : AvailabilityRequirement
    , mav : ModifiedAttackVector
    , mac : ModifiedAttackComplexity
    , mpr : ModifiedPrivilegesRequired
    , mui : ModifiedUserInteraction
    , ms : ModifiedScope
    , mc : ModifiedConfidentialityImpact
    , mi : ModifiedIntegrityImpact
    , ma : ModifiedAvailabilityImpact
    }


type AttackVector
    = AvNetwork
    | AvAdjacentNetwork
    | AvLocal
    | AvPhysical


type ModifiedAttackVector
    = MavNotDefined
    | Mav AttackVector


type AttackComplexity
    = AcLow
    | AcHigh


type ModifiedAttackComplexity
    = MacNotDefined
    | Mac AttackComplexity


type PrivilegesRequired
    = PrNone
    | PrLow
    | PrHigh


type ModifiedPrivilegesRequired
    = MprNotDefined
    | Mpr PrivilegesRequired


type UserInteraction
    = UiNone
    | UiRequired


type ModifiedUserInteraction
    = MuiNotDefined
    | Mui UserInteraction


type Scope
    = SUnchanged
    | SChanged


type ModifiedScope
    = MsNotDefined
    | Ms Scope


type ConfidentialityImpact
    = CNone
    | CLow
    | CHigh


type ModifiedConfidentialityImpact
    = McNotDefined
    | Mc ConfidentialityImpact


type IntegrityImpact
    = INone
    | ILow
    | IHigh


type ModifiedIntegrityImpact
    = MiNotDefined
    | Mi IntegrityImpact


type AvailabilityImpact
    = ANone
    | ALow
    | AHigh


type ModifiedAvailabilityImpact
    = MaNotDefined
    | Ma AvailabilityImpact


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


type ConfidentialityRequirement
    = CrNotDefined
    | CrLow
    | CrMedium
    | CrHigh


type IntegrityRequirement
    = IrNotDefined
    | IrLow
    | IrMedium
    | IrHigh


type AvailabilityRequirement
    = ArNotDefined
    | ArLow
    | ArMedium
    | ArHigh


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

        EnvironmentalVector value ->
            calculateEnvironmentalScore value


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


calculateEnvironmentalScore : EnvironmentalVectorValue -> Float
calculateEnvironmentalScore value =
    let
        impact =
            modifiedImpactSubScore value

        exploitability =
            modifiedExploitabilitySubScore value

        exploitCodeMaturity =
            toFloatExploitCodeMaturity value.temp.e

        remediationLevel =
            toFloatRemediationLevel value.temp.rl

        reportConfidence =
            toFloatReportConfidence value.temp.rc

        unchanged =
            roundUp (roundUp (min (impact + exploitability) 10) * exploitCodeMaturity * remediationLevel * reportConfidence)

        changed =
            roundUp (roundUp (min (1.08 * (impact + exploitability)) 10) * exploitCodeMaturity * remediationLevel * reportConfidence)
    in
    if impact <= 0 then
        0.0

    else
        case value.ms of
            MsNotDefined ->
                case value.temp.base.s of
                    SUnchanged ->
                        unchanged

                    SChanged ->
                        changed

            Ms scopeValue ->
                case scopeValue of
                    SUnchanged ->
                        unchanged

                    SChanged ->
                        changed


modifiedImpactSubScore : EnvironmentalVectorValue -> Float
modifiedImpactSubScore value =
    let
        modifiedIscBase =
            modifiedImpactSubScoreBase value

        unchanged =
            6.42 * modifiedIscBase

        changed =
            (7.52 * (modifiedIscBase - 0.029)) - (3.25 * (modifiedIscBase * 0.9731 - 0.02) ^ 13)
    in
    case value.ms of
        MsNotDefined ->
            case value.temp.base.s of
                SUnchanged ->
                    unchanged

                SChanged ->
                    changed

        Ms scopeValue ->
            case scopeValue of
                SUnchanged ->
                    unchanged

                SChanged ->
                    changed


modifiedImpactSubScoreBase : EnvironmentalVectorValue -> Float
modifiedImpactSubScoreBase value =
    let
        impactConf =
            1 - toFloatConfidentialityRequirements value.cr * toFloatModifiedConfidentialityImpact value.mc value.temp.base.c

        impactInteg =
            1 - toFloatIntegrityRequirements value.ir * toFloatModifiedIntegrityImpact value.mi value.temp.base.i

        impactAvail =
            1 - toFloatAvailabilityRequirements value.ar * toFloatModifiedAvailabilityImpact value.ma value.temp.base.a
    in
    min (1 - (impactConf * impactInteg * impactAvail)) 0.915


modifiedExploitabilitySubScore : EnvironmentalVectorValue -> Float
modifiedExploitabilitySubScore value =
    let
        av =
            toFloatModifiedAttackVector value.mav value.temp.base.av

        ac =
            toFloatModifiedAttackComplexity value.mac value.temp.base.ac

        pr =
            toFloatModifiedPrivilegesRequired value.ms value.mpr value.temp.base.s value.temp.base.pr

        ui =
            toFloatModifiedUserInteraction value.mui value.temp.base.ui
    in
    8.22 * av * ac * pr * ui



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


toFloatModifiedAttackVector : ModifiedAttackVector -> AttackVector -> Float
toFloatModifiedAttackVector mav base =
    case mav of
        MavNotDefined ->
            toFloatAttackVector base

        Mav value ->
            toFloatAttackVector value


toFloatAttackComplexity : AttackComplexity -> Float
toFloatAttackComplexity ac =
    case ac of
        AcLow ->
            0.77

        AcHigh ->
            0.44


toFloatModifiedAttackComplexity : ModifiedAttackComplexity -> AttackComplexity -> Float
toFloatModifiedAttackComplexity mac base =
    case mac of
        MacNotDefined ->
            toFloatAttackComplexity base

        Mac value ->
            toFloatAttackComplexity value


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


toFloatModifiedPrivilegesRequired : ModifiedScope -> ModifiedPrivilegesRequired -> Scope -> PrivilegesRequired -> Float
toFloatModifiedPrivilegesRequired ms mpr baseScope basePr =
    case ms of
        MsNotDefined ->
            case mpr of
                MprNotDefined ->
                    toFloatPrivilegesRequired baseScope basePr

                Mpr prValue ->
                    toFloatPrivilegesRequired baseScope prValue

        Ms scopeValue ->
            case mpr of
                MprNotDefined ->
                    toFloatPrivilegesRequired scopeValue basePr

                Mpr prValue ->
                    toFloatPrivilegesRequired scopeValue prValue


toFloatUserInteraction : UserInteraction -> Float
toFloatUserInteraction ui =
    case ui of
        UiNone ->
            0.85

        UiRequired ->
            0.62


toFloatModifiedUserInteraction : ModifiedUserInteraction -> UserInteraction -> Float
toFloatModifiedUserInteraction mui base =
    case mui of
        MuiNotDefined ->
            toFloatUserInteraction base

        Mui value ->
            toFloatUserInteraction value


toFloatConfidentialityImpact : ConfidentialityImpact -> Float
toFloatConfidentialityImpact c =
    case c of
        CHigh ->
            0.56

        CLow ->
            0.22

        CNone ->
            0


toFloatModifiedConfidentialityImpact : ModifiedConfidentialityImpact -> ConfidentialityImpact -> Float
toFloatModifiedConfidentialityImpact mc base =
    case mc of
        McNotDefined ->
            toFloatConfidentialityImpact base

        Mc value ->
            toFloatConfidentialityImpact value


toFloatIntegrityImpact : IntegrityImpact -> Float
toFloatIntegrityImpact i =
    case i of
        IHigh ->
            0.56

        ILow ->
            0.22

        INone ->
            0.0


toFloatModifiedIntegrityImpact : ModifiedIntegrityImpact -> IntegrityImpact -> Float
toFloatModifiedIntegrityImpact mi base =
    case mi of
        MiNotDefined ->
            toFloatIntegrityImpact base

        Mi value ->
            toFloatIntegrityImpact value


toFloatAvailabilityImpact : AvailabilityImpact -> Float
toFloatAvailabilityImpact a =
    case a of
        AHigh ->
            0.56

        ALow ->
            0.22

        ANone ->
            0.0


toFloatModifiedAvailabilityImpact : ModifiedAvailabilityImpact -> AvailabilityImpact -> Float
toFloatModifiedAvailabilityImpact ma base =
    case ma of
        MaNotDefined ->
            toFloatAvailabilityImpact base

        Ma value ->
            toFloatAvailabilityImpact value


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


toFloatConfidentialityRequirements : ConfidentialityRequirement -> Float
toFloatConfidentialityRequirements cr =
    case cr of
        CrNotDefined ->
            toFloatConfidentialityRequirements CrMedium

        CrLow ->
            0.5

        CrMedium ->
            1.0

        CrHigh ->
            1.5


toFloatIntegrityRequirements : IntegrityRequirement -> Float
toFloatIntegrityRequirements ir =
    case ir of
        IrNotDefined ->
            toFloatIntegrityRequirements IrMedium

        IrLow ->
            0.5

        IrMedium ->
            1.0

        IrHigh ->
            1.5


toFloatAvailabilityRequirements : AvailabilityRequirement -> Float
toFloatAvailabilityRequirements ar =
    case ar of
        ArNotDefined ->
            toFloatAvailabilityRequirements ArMedium

        ArLow ->
            0.5

        ArMedium ->
            1.0

        ArHigh ->
            1.5



-- TO_STRING


toStringVector : Vector -> String
toStringVector vector =
    case vector of
        BaseVector value ->
            toStringBaseVector value

        TemporalVector value ->
            toStringTemporalVector value

        EnvironmentalVector value ->
            toStringEnvironmentalVector value


toStringEnvironmentalVector : EnvironmentalVectorValue -> String
toStringEnvironmentalVector value =
    String.dropRight 1 <|
        toStringTemporalVector value.temp
            ++ "/"
            ++ toStringConfidentialityRequirement value.cr
            ++ toStringIntegrityRequirement value.ir
            ++ toStringAvailabilityRequirement value.ar
            ++ toStringModifiedAttackVector value.mav
            ++ toStringModifiedAttackComplexity value.mac
            ++ toStringModifiedPrivilegesRequired value.mpr
            ++ toStringModifiedUserInteraction value.mui
            ++ toStringModifiedScope value.ms
            ++ toStringModifiedConfidentialityImpact value.mc
            ++ toStringModifiedIntegrityImpact value.mi
            ++ toStringModifiedAvailabilityImpact value.ma


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


toStringModifiedAttackVector : ModifiedAttackVector -> String
toStringModifiedAttackVector mav =
    case mav of
        MavNotDefined ->
            ""

        Mav value ->
            String.append "M" <| toStringAttackVector value


toStringAttackComplexity : AttackComplexity -> String
toStringAttackComplexity ac =
    case ac of
        AcLow ->
            "AC:L/"

        AcHigh ->
            "AC:H/"


toStringModifiedAttackComplexity : ModifiedAttackComplexity -> String
toStringModifiedAttackComplexity mac =
    case mac of
        MacNotDefined ->
            ""

        Mac value ->
            String.append "M" <| toStringAttackComplexity value


toStringPrivilegesRequired : PrivilegesRequired -> String
toStringPrivilegesRequired pr =
    case pr of
        PrNone ->
            "PR:N/"

        PrLow ->
            "PR:L/"

        PrHigh ->
            "PR:H/"


toStringModifiedPrivilegesRequired : ModifiedPrivilegesRequired -> String
toStringModifiedPrivilegesRequired mpr =
    case mpr of
        MprNotDefined ->
            ""

        Mpr value ->
            String.append "M" <| toStringPrivilegesRequired value


toStringUserInteraction : UserInteraction -> String
toStringUserInteraction ui =
    case ui of
        UiNone ->
            "UI:N/"

        UiRequired ->
            "UI:R/"


toStringModifiedUserInteraction : ModifiedUserInteraction -> String
toStringModifiedUserInteraction mui =
    case mui of
        MuiNotDefined ->
            ""

        Mui value ->
            String.append "M" <| toStringUserInteraction value


toStringScope : Scope -> String
toStringScope s =
    case s of
        SUnchanged ->
            "S:U/"

        SChanged ->
            "S:C/"


toStringModifiedScope : ModifiedScope -> String
toStringModifiedScope ms =
    case ms of
        MsNotDefined ->
            ""

        Ms value ->
            String.append "M" <| toStringScope value


toStringConfidentialityImpact : ConfidentialityImpact -> String
toStringConfidentialityImpact c =
    case c of
        CNone ->
            "C:N/"

        CLow ->
            "C:L/"

        CHigh ->
            "C:H/"


toStringModifiedConfidentialityImpact : ModifiedConfidentialityImpact -> String
toStringModifiedConfidentialityImpact mc =
    case mc of
        McNotDefined ->
            ""

        Mc value ->
            String.append "M" <| toStringConfidentialityImpact value


toStringIntegrityImpact : IntegrityImpact -> String
toStringIntegrityImpact i =
    case i of
        INone ->
            "I:N/"

        ILow ->
            "I:L/"

        IHigh ->
            "I:H/"


toStringModifiedIntegrityImpact : ModifiedIntegrityImpact -> String
toStringModifiedIntegrityImpact mi =
    case mi of
        MiNotDefined ->
            ""

        Mi value ->
            String.append "M" <| toStringIntegrityImpact value


toStringAvailabilityImpact : AvailabilityImpact -> String
toStringAvailabilityImpact a =
    case a of
        ANone ->
            "A:N/"

        ALow ->
            "A:L/"

        AHigh ->
            "A:H/"


toStringModifiedAvailabilityImpact : ModifiedAvailabilityImpact -> String
toStringModifiedAvailabilityImpact ma =
    case ma of
        MaNotDefined ->
            ""

        Ma value ->
            String.append "M" <| toStringAvailabilityImpact value


toStringExploitCodeMaturity : ExploitCodeMaturity -> String
toStringExploitCodeMaturity em =
    case em of
        ENotDefined ->
            ""

        EUnproven ->
            "E:U/"

        EProofOfConcept ->
            "E:P/"

        EFunctional ->
            "E:F/"

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


toStringConfidentialityRequirement : ConfidentialityRequirement -> String
toStringConfidentialityRequirement cr =
    case cr of
        CrNotDefined ->
            ""

        CrLow ->
            "CR:L/"

        CrMedium ->
            "CR:M/"

        CrHigh ->
            "CR:H/"


toStringIntegrityRequirement : IntegrityRequirement -> String
toStringIntegrityRequirement ir =
    case ir of
        IrNotDefined ->
            ""

        IrLow ->
            "IR:L/"

        IrMedium ->
            "IR:M/"

        IrHigh ->
            "IR:H/"


toStringAvailabilityRequirement : AvailabilityRequirement -> String
toStringAvailabilityRequirement ar =
    case ar of
        ArNotDefined ->
            ""

        ArLow ->
            "AR:L/"

        ArMedium ->
            "AR:M/"

        ArHigh ->
            "AR:H/"


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

        EnvironmentalVectorChoice ->
            Random.Extra.filter (\vector -> isInRange <| calculateScore vector) randomEnvironmentalVector


randomVector : VectorChoice -> Random.Generator Vector
randomVector choice =
    case choice of
        BaseVectorChoice ->
            randomBaseVector

        TemporalVectorChoice ->
            randomTemporalVector

        EnvironmentalVectorChoice ->
            randomEnvironmentalVector


randomEnvironmentalVector : Random.Generator Vector
randomEnvironmentalVector =
    let
        temporalVectorValue =
            Random.map extractTemporalVectorValue randomTemporalVector
    in
    Random.map EnvironmentalVector
        (Random.map EnvironmentalVectorValue temporalVectorValue
            |> andMap randomConfidentialityRequirement
            |> andMap randomIntegrityRequirement
            |> andMap randomAvailabilityRequirement
            |> andMap randomModifiedAttackVector
            |> andMap randomModifiedAttackComplexity
            |> andMap randomModifiedPrivilegesRequired
            |> andMap randomModifiedUserInteraction
            |> andMap randomModifiedScope
            |> andMap randomModifiedConfidentialityImpact
            |> andMap randomModifiedIntegrityImpact
            |> andMap randomModifiedAvailabilityImpact
        )


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


randomModifiedAttackVector : Random.Generator ModifiedAttackVector
randomModifiedAttackVector =
    Random.uniform MavNotDefined <|
        List.map Mav [ AvNetwork, AvAdjacentNetwork, AvLocal, AvPhysical ]


randomAttackComplexity : Random.Generator AttackComplexity
randomAttackComplexity =
    Random.uniform AcLow [ AcHigh ]


randomModifiedAttackComplexity : Random.Generator ModifiedAttackComplexity
randomModifiedAttackComplexity =
    Random.uniform MacNotDefined <|
        List.map Mac [ AcLow, AcHigh ]


randomPrivilegesRequired : Random.Generator PrivilegesRequired
randomPrivilegesRequired =
    Random.uniform PrNone [ PrLow, PrHigh ]


randomModifiedPrivilegesRequired : Random.Generator ModifiedPrivilegesRequired
randomModifiedPrivilegesRequired =
    Random.uniform MprNotDefined <|
        List.map Mpr [ PrNone, PrLow, PrHigh ]


randomUserInteraction : Random.Generator UserInteraction
randomUserInteraction =
    Random.uniform UiNone [ UiRequired ]


randomModifiedUserInteraction : Random.Generator ModifiedUserInteraction
randomModifiedUserInteraction =
    Random.uniform MuiNotDefined <|
        List.map Mui [ UiNone, UiRequired ]


randomScope : Random.Generator Scope
randomScope =
    Random.uniform SUnchanged [ SChanged ]


randomModifiedScope : Random.Generator ModifiedScope
randomModifiedScope =
    Random.uniform MsNotDefined <|
        List.map Ms [ SUnchanged, SChanged ]


randomConfidentialityImpact : Random.Generator ConfidentialityImpact
randomConfidentialityImpact =
    Random.uniform CNone [ CLow, CHigh ]


randomModifiedConfidentialityImpact : Random.Generator ModifiedConfidentialityImpact
randomModifiedConfidentialityImpact =
    Random.uniform McNotDefined <|
        List.map Mc [ CNone, CLow, CHigh ]


randomIntegrityImpact : Random.Generator IntegrityImpact
randomIntegrityImpact =
    Random.uniform INone [ ILow, IHigh ]


randomModifiedIntegrityImpact : Random.Generator ModifiedIntegrityImpact
randomModifiedIntegrityImpact =
    Random.uniform MiNotDefined <|
        List.map Mi [ INone, ILow, IHigh ]


randomAvailabilityImpact : Random.Generator AvailabilityImpact
randomAvailabilityImpact =
    Random.uniform ANone [ ALow, AHigh ]


randomModifiedAvailabilityImpact : Random.Generator ModifiedAvailabilityImpact
randomModifiedAvailabilityImpact =
    Random.uniform MaNotDefined <|
        List.map Ma [ ANone, ALow, AHigh ]


randomExploitCodeMaturity : Random.Generator ExploitCodeMaturity
randomExploitCodeMaturity =
    Random.uniform ENotDefined [ EUnproven, EProofOfConcept, EFunctional, EHigh ]


randomRemediationLevel : Random.Generator RemediationLevel
randomRemediationLevel =
    Random.uniform RlNotDefined [ RlOfficialFix, RlTemporaryFix, RlWorkaround, RlUnavailable ]


randomReportConfidence : Random.Generator ReportConfidence
randomReportConfidence =
    Random.uniform RcNotDefined [ RcUnknown, RcReasonable, RcConfirmed ]


randomConfidentialityRequirement : Random.Generator ConfidentialityRequirement
randomConfidentialityRequirement =
    Random.uniform CrNotDefined [ CrLow, CrMedium, CrHigh ]


randomIntegrityRequirement : Random.Generator IntegrityRequirement
randomIntegrityRequirement =
    Random.uniform IrNotDefined [ IrLow, IrMedium, IrHigh ]


randomAvailabilityRequirement : Random.Generator AvailabilityRequirement
randomAvailabilityRequirement =
    Random.uniform ArNotDefined [ ArLow, ArMedium, ArHigh ]



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

        EnvironmentalVector value ->
            value.temp.base


extractTemporalVectorValue : Vector -> TemporalVectorValue
extractTemporalVectorValue vector =
    case vector of
        BaseVector value ->
            TemporalVectorValue value ENotDefined RlNotDefined RcNotDefined

        TemporalVector value ->
            value

        EnvironmentalVector value ->
            value.temp
