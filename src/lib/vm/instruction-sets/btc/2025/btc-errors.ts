/**
 * Extra VM errors introduced by the BTC-limits implementation.
 * (Everything else re-uses AuthenticationErrorCommon.)
 */
export enum AuthenticationErrorBTC {
    excessiveHashing =
        'Excessive cumulative hash-digest iterations (ConsensusBTC.maximumHashDigestIterations exceeded)',
}
