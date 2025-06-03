import {
    hash256,
    ripemd160 as internalRipemd160,
    secp256k1 as internalSecp256k1,
    sha1 as internalSha1,
    sha256 as internalSha256
} from '../../../../crypto/crypto.js';
import { binToHex } from '../../../../format/format.js';

import type {
    AuthenticationProgramStateError,
    AuthenticationProgramStateMinimum,
    AuthenticationProgramStateResourceLimitsBTC,
    AuthenticationProgramStateStack,
    Operation,
    Ripemd160,
    Secp256k1,
    Sha1,
    Sha256
} from '../../../../lib.js';

import {
    applyError,
    AuthenticationErrorCommon,
    booleanToVmNumber,
    combineOperations,
    ConsensusCommon,
    decodeBitcoinSignature,
    encodeAuthenticationInstructions,
    generateSigningSerializationBCH as generateSigningSerializationLegacy,
    isValidPublicKeyEncoding,
    isValidSignatureEncodingTransaction,
    opVerify,
    pushToStack,
    useOneStackItem,
    useOneVmNumber,
    useTwoStackItems
} from '../../common/common.js';
import { AuthenticationErrorBTC } from './btc-errors.js';

import type { AuthenticationProgramStateBTC } from './btc-types.js';
import { ConsensusBTC } from './btc-types.js';

export type Secp256k1Verify = Pick<
    Secp256k1,
    'verifySignatureSchnorr' | 'verifySignatureDERLowS'
>;

export const hashDigestIterationsBTC = (len: number) =>
    1 + (((len + 8) / 64) | 0);

export const incrementHashDigestIterationsBTC = <
    State extends AuthenticationProgramStateError &
        AuthenticationProgramStateResourceLimitsBTC,
>(
    state: State,
    messageLength: number,
    op: (next: State) => State
) => {
    const total = state.hashDigestIterations + hashDigestIterationsBTC(messageLength);
    return total > ConsensusBTC.maximumHashDigestIterations
        ? applyError(
            state,
            AuthenticationErrorBTC.excessiveHashing,
            `Required cumulative iterations: ${total}`
        )
        : op(state);
};

export const validLegacySigningSerializationTypes = [
    0x01, 0x02, 0x03, 0x81, 0x82, 0x83
] as const;

export const opRipemd160BtcLimits =
    <
        State extends AuthenticationProgramStateError &
            AuthenticationProgramStateMinimum &
            AuthenticationProgramStateResourceLimitsBTC &
            AuthenticationProgramStateStack,
    >(
        { ripemd160 }: { ripemd160: { hash: Ripemd160['hash'] } } = {
            ripemd160: internalRipemd160
        }
    ): Operation<State> =>
        (s) =>
            useOneStackItem(s, (ns, [v]) =>
                incrementHashDigestIterationsBTC(ns, v.length, (fs) =>
                    pushToStack(fs, ripemd160.hash(v))
                )
            );

export const opSha1BtcLimits =
    <
        State extends AuthenticationProgramStateError &
            AuthenticationProgramStateMinimum &
            AuthenticationProgramStateResourceLimitsBTC &
            AuthenticationProgramStateStack,
    >(
        { sha1 }: { sha1: { hash: Sha1['hash'] } } = { sha1: internalSha1 }
    ): Operation<State> =>
        (s) =>
            useOneStackItem(s, (ns, [v]) =>
                incrementHashDigestIterationsBTC(ns, v.length, (fs) =>
                    pushToStack(fs, sha1.hash(v))
                )
            );

export const opSha256BtcLimits =
    <
        State extends AuthenticationProgramStateError &
            AuthenticationProgramStateMinimum &
            AuthenticationProgramStateResourceLimitsBTC &
            AuthenticationProgramStateStack,
    >(
        { sha256 }: { sha256: { hash: Sha256['hash'] } } = {
            sha256: internalSha256
        }
    ): Operation<State> =>
        (s) =>
            useOneStackItem(s, (ns, [v]) =>
                incrementHashDigestIterationsBTC(ns, v.length, (fs) =>
                    pushToStack(fs, sha256.hash(v))
                )
            );

export const opHash160BtcLimits =
    <
        State extends AuthenticationProgramStateError &
            AuthenticationProgramStateMinimum &
            AuthenticationProgramStateResourceLimitsBTC &
            AuthenticationProgramStateStack,
    >(
        {
            ripemd160,
            sha256
        }: {
            sha256: { hash: Sha256['hash'] };
            ripemd160: { hash: Ripemd160['hash'] };
        } = { ripemd160: internalRipemd160, sha256: internalSha256 }
    ): Operation<State> =>
        (s) =>
            useOneStackItem(s, (ns, [v]) =>
                incrementHashDigestIterationsBTC(ns, v.length, (fs) =>
                    pushToStack(fs, ripemd160.hash(sha256.hash(v)))
                )
            );

export const opHash256BtcLimits =
    <
        State extends AuthenticationProgramStateError &
            AuthenticationProgramStateMinimum &
            AuthenticationProgramStateResourceLimitsBTC &
            AuthenticationProgramStateStack,
    >(
        { sha256 }: { sha256: { hash: Sha256['hash'] } } = {
            sha256: internalSha256
        }
    ): Operation<State> =>
        (s) =>
            useOneStackItem(s, (ns, [v]) =>
                incrementHashDigestIterationsBTC(ns, v.length, (fs) =>
                    pushToStack(fs, hash256(v, sha256))
                )
            );

export const opCheckSigBtcLimits =
    <State extends AuthenticationProgramStateBTC>(
        {
            secp256k1,
            sha256
        }: {
            sha256: { hash: Sha256['hash'] };
            secp256k1: Secp256k1Verify;
        } = { secp256k1: internalSecp256k1, sha256: internalSha256 }
    ): Operation<State> =>
        (s) =>
            useTwoStackItems(s, (state, [encSig, pubKey]) => {
                if (!isValidPublicKeyEncoding(pubKey)) {
                    return applyError(state, AuthenticationErrorCommon.invalidPublicKeyEncoding);
                }
                if (
                    !isValidSignatureEncodingTransaction(
                        encSig,
                        validLegacySigningSerializationTypes
                    )
                ) {
                    return applyError(
                        state,
                        AuthenticationErrorCommon.invalidSignatureEncoding,
                        `Transaction signature (incl. sighash flag): ${binToHex(encSig)}`
                    );
                }

                const coveredBytecode = encodeAuthenticationInstructions(
                    state.instructions
                ).subarray(state.lastCodeSeparator + 1);

                const { signingSerializationType, signature } =
                    decodeBitcoinSignature(encSig);

                const serialization = generateSigningSerializationLegacy(
                    state.program,
                    { coveredBytecode, signingSerializationType },
                    sha256
                );

                const total =
                    state.hashDigestIterations + hashDigestIterationsBTC(serialization.length);

                if (total > ConsensusBTC.maximumHashDigestIterations) {
                    return applyError(
                        state,
                        AuthenticationErrorBTC.excessiveHashing,
                        `Required cumulative iterations: ${total}`
                    );
                }

                const digest = hash256(serialization, sha256);

                state.signedMessages.push({ digest, serialization });

                const schnorr = signature.length === ConsensusCommon.schnorrSignatureLength;
                const signatureOk = schnorr
                    ? secp256k1.verifySignatureSchnorr(signature, pubKey, digest)
                    : secp256k1.verifySignatureDERLowS(signature, pubKey, digest);

                return !signatureOk && signature.length !== 0
                    ? applyError(state, AuthenticationErrorCommon.nonNullSignatureFailure)
                    : pushToStack(state, booleanToVmNumber(signatureOk));
            });

const enum Multisig { maximumPublicKeys = 20 }

export const opCheckMultiSigBtcLimits =
    <State extends AuthenticationProgramStateBTC>(
        {
            secp256k1,
            sha256
        }: {
            sha256: { hash: Sha256['hash'] };
            secp256k1: Secp256k1Verify;
        } = { secp256k1: internalSecp256k1, sha256: internalSha256 }
    ): Operation<State> =>
        (s) =>
            useOneVmNumber(s, (state, pubKeyCountVm) => {
                const pubKeyCount = Number(pubKeyCountVm);

                if (pubKeyCount < 0) {
                    return applyError(state, AuthenticationErrorCommon.invalidNaturalNumber);
                }
                if (pubKeyCount > Multisig.maximumPublicKeys) {
                    return applyError(
                        state,
                        AuthenticationErrorCommon.exceedsMaximumMultisigPublicKeyCount
                    );
                }

                const publicKeys =
                    pubKeyCount > 0 ? state.stack.splice(-pubKeyCount) : [];

                return useOneVmNumber(state, (ns, sigCountVm) => {
                    const sigCount = Number(sigCountVm);

                    if (sigCount < 0) {
                        return applyError(ns, AuthenticationErrorCommon.invalidNaturalNumber);
                    }
                    if (sigCount > pubKeyCount) {
                        return applyError(ns, AuthenticationErrorCommon.insufficientPublicKeys);
                    }

                    const signatures = sigCount > 0 ? ns.stack.splice(-sigCount) : [];

                    return useOneStackItem(ns, (fs, [bug]) => {
                        if (bug.length !== 0) {
                            return applyError(fs, AuthenticationErrorCommon.invalidProtocolBugValue);
                        }

                        const coveredBytecode = encodeAuthenticationInstructions(
                            fs.instructions
                        ).subarray(fs.lastCodeSeparator + 1);

                        let approved = 0;
                        let remainingSigs = signatures.length;
                        let remainingPubs = publicKeys.length;

                        while (
                            remainingSigs > 0 &&
                            remainingPubs > 0 &&
                            approved + remainingPubs >= remainingSigs &&
                            approved !== sigCount
                            ) {
                            const pub = publicKeys[--remainingPubs]!;
                            const enc = signatures[--remainingSigs]!;

                            if (!isValidPublicKeyEncoding(pub)) {
                                return applyError(fs, AuthenticationErrorCommon.invalidPublicKeyEncoding);
                            }
                            if (
                                !isValidSignatureEncodingTransaction(
                                    enc,
                                    validLegacySigningSerializationTypes
                                )
                            ) {
                                return applyError(
                                    fs,
                                    AuthenticationErrorCommon.invalidSignatureEncoding,
                                    `Transaction signature (incl. sighash flag): ${binToHex(enc)}`
                                );
                            }

                            const { signingSerializationType, signature } =
                                decodeBitcoinSignature(enc);

                            const serialization = generateSigningSerializationLegacy(
                                fs.program,
                                { coveredBytecode, signingSerializationType },
                                sha256
                            );

                            const total =
                                fs.hashDigestIterations + hashDigestIterationsBTC(serialization.length);
                            if (total > ConsensusBTC.maximumHashDigestIterations) {
                                return applyError(
                                    fs,
                                    AuthenticationErrorBTC.excessiveHashing,
                                    `Required cumulative iterations: ${total}`
                                );
                            }

                            const digest = hash256(serialization, sha256);

                            fs.signedMessages.push({ digest, serialization });

                            if (signature.length === ConsensusCommon.schnorrSignatureLength) {
                                return applyError(
                                    fs,
                                    AuthenticationErrorCommon.schnorrSizedSignatureInCheckMultiSig
                                );
                            }

                            if (secp256k1.verifySignatureDERLowS(signature, pub, digest)) {
                                ++approved;
                            }
                        }

                        const success = approved === sigCount;

                        return !success && !signatures.every((sig) => sig.length === 0)
                            ? applyError(fs, AuthenticationErrorCommon.nonNullSignatureFailure)
                            : pushToStack(fs, booleanToVmNumber(success));
                    });
                });
            });


export const opCheckSigVerifyBtcLimits = <
    State extends AuthenticationProgramStateBTC,
>(
    params: { secp256k1: Secp256k1Verify; sha256: { hash: Sha256['hash'] } } = {
        secp256k1: internalSecp256k1,
        sha256: internalSha256
    }
): Operation<State> =>
    combineOperations(opCheckSigBtcLimits<State>(params), opVerify);

export const opCheckMultiSigVerifyBtcLimits = <
    State extends AuthenticationProgramStateBTC,
>(
    params: { secp256k1: Secp256k1Verify; sha256: { hash: Sha256['hash'] } } = {
        secp256k1: internalSecp256k1,
        sha256: internalSha256
    }
): Operation<State> =>
    combineOperations(opCheckMultiSigBtcLimits<State>(params), opVerify);
