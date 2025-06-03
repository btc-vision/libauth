import { isPayToScriptHash20 } from '../../../../address/address.js';
import {
    ripemd160 as internalRipemd160,
    secp256k1 as internalSecp256k1,
    sha1 as internalSha1,
    sha256 as internalSha256
} from '../../../../crypto/crypto.js';

import type {
    AuthenticationProgramCommon as AuthenticationProgramBTC,
    AuthenticationProgramStateBTC,
    InstructionSet,
    ResolvedTransactionCommon as ResolvedTransactionBTC,
    Ripemd160,
    Secp256k1Verify,
    Sha1,
    Sha256
} from '../../../../lib.js';
import { encodeTransaction as encodeTransactionBTC } from '../../../../message/message.js';

import {
    applyError,
    AuthenticationErrorCommon,
    authenticationInstructionsAreMalformed,
    cloneStack,
    decodeAuthenticationInstructions,
    disabledOperation,
    isArbitraryDataOutput,
    isPushOnly,
    isStandardOutputBytecode,
    isWitnessProgram,
    op0NotEqual,
    op1Add,
    op1Sub,
    op2Drop,
    op2Dup,
    op2Over,
    op2Rot,
    op2Swap,
    op3Dup,
    opAbs,
    opAdd,
    opAnd,
    opBoolAnd,
    opBoolOr,
    opCat,
    opCheckLockTimeVerify,
    opCheckSequenceVerify,
    opCodeSeparator,
    opDepth,
    opDiv,
    opDrop,
    opDup,
    opEqual,
    opEqualVerify,
    opFromAltStack,
    opGreaterThan,
    opGreaterThanOrEqual,
    opIfDup,
    opLessThan,
    opLessThanOrEqual,
    opMax,
    opMin,
    opMod,
    opMul,
    opNegate,
    opNip,
    opNop,
    opNopDisallowed,
    opNot,
    opNumEqual,
    opNumEqualVerify,
    opNumNotEqual,
    opOr,
    opOver,
    opPick,
    opReturn,
    opRoll,
    opRot,
    opSize,
    opSub,
    opSwap,
    opToAltStack,
    opTuck,
    opVerify,
    opWithin,
    opXor,
    pushNumberOperation,
    reservedOperation,
    stackItemIsTruthy
} from '../../common/common.js';

import {
    opCheckMultiSigBtcLimits,
    opCheckMultiSigVerifyBtcLimits,
    opCheckSigBtcLimits,
    opCheckSigVerifyBtcLimits,
    opHash160BtcLimits,
    opHash256BtcLimits,
    opRipemd160BtcLimits,
    opSha1BtcLimits,
    opSha256BtcLimits
} from './btc-crypto.js';

import {
    conditionallyEvaluateBtc,
    opElseBtc,
    opEndIfBtc,
    opIfBtc,
    opNotIfBtc,
    pushOperationBtc,
    undefinedOperationBtc
} from './btc-loops.js';

import { OpcodesBTC } from './btc-opcodes.js';
import { cloneAuthenticationProgramStateBTC, ConsensusBTC, createAuthenticationProgramStateBTC } from './btc-types.js';

export const createInstructionSetBTC = (
    standard = true,
    {
        ripemd160,
        secp256k1,
        sha1,
        sha256
    }: {
        ripemd160: { hash: Ripemd160['hash'] };
        secp256k1: Secp256k1Verify;
        sha1: { hash: Sha1['hash'] };
        sha256: { hash: Sha256['hash'] };
    } = {
        ripemd160: internalRipemd160,
        secp256k1: internalSecp256k1,
        sha1: internalSha1,
        sha256: internalSha256
    }
): InstructionSet<
    ResolvedTransactionBTC,
    AuthenticationProgramBTC,
    AuthenticationProgramStateBTC
> => {

    const conditionallyPush =
        pushOperationBtc<AuthenticationProgramStateBTC>();

    return {

        clone: cloneAuthenticationProgramStateBTC,
        continue: (s) =>
            s.error === undefined && s.ip < s.instructions.length,

        evaluate: (program, stateEvaluate) => {

            const { unlockingBytecode } =
                program.transaction.inputs[program.inputIndex]!;
            const { lockingBytecode } =
                program.sourceOutputs[program.inputIndex]!;

            const unlockingInstr = decodeAuthenticationInstructions(unlockingBytecode);
            const lockingInstr = decodeAuthenticationInstructions(lockingBytecode);

            const initialState = createAuthenticationProgramStateBTC({
                instructions: unlockingInstr,
                program,
                stack: []
            });

            if (unlockingBytecode.length > ConsensusBTC.maximumBytecodeLength) {
                return applyError(
                    initialState,
                    `Unlocking bytecode (${unlockingBytecode.length} B) exceeds ConsensusBTC.maximumBytecodeLength.`
                );
            }
            if (authenticationInstructionsAreMalformed(unlockingInstr)) {
                return applyError(initialState, AuthenticationErrorCommon.malformedUnlockingBytecode);
            }
            if (!isPushOnly(unlockingBytecode)) {
                return applyError(initialState, AuthenticationErrorCommon.requiresPushOnly);
            }

            if (lockingBytecode.length > ConsensusBTC.maximumBytecodeLength) {
                return applyError(initialState, AuthenticationErrorCommon.exceededMaximumBytecodeLengthLocking);
            }
            if (authenticationInstructionsAreMalformed(lockingInstr)) {
                return applyError(initialState, AuthenticationErrorCommon.malformedLockingBytecode);
            }

            const unlockResult = stateEvaluate(initialState);
            if (unlockResult.error !== undefined) return unlockResult;
            if (unlockResult.controlStack.length !== 0) {
                return applyError(initialState, AuthenticationErrorCommon.nonEmptyControlStack);
            }

            const lockResult = stateEvaluate(
                createAuthenticationProgramStateBTC({
                    instructions: lockingInstr,
                    program,
                    stack: unlockResult.stack
                })
            );

            if (!isPayToScriptHash20(lockingBytecode)) return lockResult;

            const p2shStack = cloneStack(unlockResult.stack);
            const p2shScript = p2shStack.pop() ?? Uint8Array.of();

            if (p2shStack.length === 0 && isWitnessProgram(p2shScript)) {
                return lockResult;
            }

            const p2shInstructions = decodeAuthenticationInstructions(p2shScript);
            return authenticationInstructionsAreMalformed(p2shInstructions)
                ? { ...lockResult, error: AuthenticationErrorCommon.malformedP2shBytecode }
                : stateEvaluate(
                    createAuthenticationProgramStateBTC({
                        instructions: p2shInstructions,
                        program,
                        stack: p2shStack
                    })
                );
        },

        every: (state) =>
            state.stack.length + state.alternateStack.length >
            ConsensusBTC.maximumStackDepth
                ? applyError(state, AuthenticationErrorCommon.exceededMaximumStackDepth)
                : state,

        operations: {

            [OpcodesBTC.OP_0]: conditionallyPush,

            ...Object.fromEntries(
                [...Array(75).keys()].map((i) => [0x01 + i, conditionallyPush])
            ),
            [OpcodesBTC.OP_PUSHDATA_1]: conditionallyPush,
            [OpcodesBTC.OP_PUSHDATA_2]: conditionallyPush,
            [OpcodesBTC.OP_PUSHDATA_4]: conditionallyPush,

            [OpcodesBTC.OP_1NEGATE]:
                conditionallyEvaluateBtc(pushNumberOperation(-1)),
            [OpcodesBTC.OP_RESERVED]:
                conditionallyEvaluateBtc(reservedOperation),
            ...Object.fromEntries(
                [...Array(16).keys()].map((i) => [
                    OpcodesBTC.OP_1 + i,
                    conditionallyEvaluateBtc(pushNumberOperation(i + 1))
                ])
            ),

            [OpcodesBTC.OP_NOP]: conditionallyEvaluateBtc(opNop),
            [OpcodesBTC.OP_IF]: opIfBtc,
            [OpcodesBTC.OP_NOTIF]: opNotIfBtc,
            [OpcodesBTC.OP_ELSE]: opElseBtc,
            [OpcodesBTC.OP_ENDIF]: opEndIfBtc,
            [OpcodesBTC.OP_VERIFY]: conditionallyEvaluateBtc(opVerify),
            [OpcodesBTC.OP_RETURN]: conditionallyEvaluateBtc(opReturn),

            [OpcodesBTC.OP_TOALTSTACK]: conditionallyEvaluateBtc(opToAltStack),
            [OpcodesBTC.OP_FROMALTSTACK]: conditionallyEvaluateBtc(opFromAltStack),
            [OpcodesBTC.OP_2DROP]: conditionallyEvaluateBtc(op2Drop),
            [OpcodesBTC.OP_2DUP]: conditionallyEvaluateBtc(op2Dup),
            [OpcodesBTC.OP_3DUP]: conditionallyEvaluateBtc(op3Dup),
            [OpcodesBTC.OP_2OVER]: conditionallyEvaluateBtc(op2Over),
            [OpcodesBTC.OP_2ROT]: conditionallyEvaluateBtc(op2Rot),
            [OpcodesBTC.OP_2SWAP]: conditionallyEvaluateBtc(op2Swap),
            [OpcodesBTC.OP_IFDUP]: conditionallyEvaluateBtc(opIfDup),
            [OpcodesBTC.OP_DEPTH]: conditionallyEvaluateBtc(opDepth),
            [OpcodesBTC.OP_DROP]: conditionallyEvaluateBtc(opDrop),
            [OpcodesBTC.OP_DUP]: conditionallyEvaluateBtc(opDup),
            [OpcodesBTC.OP_NIP]: conditionallyEvaluateBtc(opNip),
            [OpcodesBTC.OP_OVER]: conditionallyEvaluateBtc(opOver),
            [OpcodesBTC.OP_PICK]: conditionallyEvaluateBtc(opPick),
            [OpcodesBTC.OP_ROLL]: conditionallyEvaluateBtc(opRoll),
            [OpcodesBTC.OP_ROT]: conditionallyEvaluateBtc(opRot),
            [OpcodesBTC.OP_SWAP]: conditionallyEvaluateBtc(opSwap),
            [OpcodesBTC.OP_TUCK]: conditionallyEvaluateBtc(opTuck),

            [OpcodesBTC.OP_CAT]: conditionallyEvaluateBtc(opCat),
            [OpcodesBTC.OP_SIZE]: conditionallyEvaluateBtc(opSize),
            [OpcodesBTC.OP_INVERT]: disabledOperation,
            [OpcodesBTC.OP_AND]: conditionallyEvaluateBtc(opAnd),
            [OpcodesBTC.OP_OR]: conditionallyEvaluateBtc(opOr),
            [OpcodesBTC.OP_XOR]: conditionallyEvaluateBtc(opXor),

            [OpcodesBTC.OP_EQUAL]: conditionallyEvaluateBtc(opEqual),
            [OpcodesBTC.OP_EQUALVERIFY]: conditionallyEvaluateBtc(opEqualVerify),
            [OpcodesBTC.OP_RESERVED1]: conditionallyEvaluateBtc(reservedOperation),
            [OpcodesBTC.OP_RESERVED2]: conditionallyEvaluateBtc(reservedOperation),
            [OpcodesBTC.OP_1ADD]: conditionallyEvaluateBtc(op1Add),
            [OpcodesBTC.OP_1SUB]: conditionallyEvaluateBtc(op1Sub),
            [OpcodesBTC.OP_2MUL]: disabledOperation,
            [OpcodesBTC.OP_2DIV]: disabledOperation,
            [OpcodesBTC.OP_NEGATE]: conditionallyEvaluateBtc(opNegate),
            [OpcodesBTC.OP_ABS]: conditionallyEvaluateBtc(opAbs),
            [OpcodesBTC.OP_NOT]: conditionallyEvaluateBtc(opNot),
            [OpcodesBTC.OP_0NOTEQUAL]: conditionallyEvaluateBtc(op0NotEqual),
            [OpcodesBTC.OP_ADD]: conditionallyEvaluateBtc(opAdd),
            [OpcodesBTC.OP_SUB]: conditionallyEvaluateBtc(opSub),
            [OpcodesBTC.OP_MUL]: conditionallyEvaluateBtc(opMul),
            [OpcodesBTC.OP_DIV]: conditionallyEvaluateBtc(opDiv),
            [OpcodesBTC.OP_MOD]: conditionallyEvaluateBtc(opMod),
            [OpcodesBTC.OP_LSHIFT]: disabledOperation,
            [OpcodesBTC.OP_RSHIFT]: disabledOperation,
            [OpcodesBTC.OP_BOOLAND]: conditionallyEvaluateBtc(opBoolAnd),
            [OpcodesBTC.OP_BOOLOR]: conditionallyEvaluateBtc(opBoolOr),
            [OpcodesBTC.OP_NUMEQUAL]: conditionallyEvaluateBtc(opNumEqual),
            [OpcodesBTC.OP_NUMEQUALVERIFY]:
                conditionallyEvaluateBtc(opNumEqualVerify),
            [OpcodesBTC.OP_NUMNOTEQUAL]:
                conditionallyEvaluateBtc(opNumNotEqual),
            [OpcodesBTC.OP_LESSTHAN]: conditionallyEvaluateBtc(opLessThan),
            [OpcodesBTC.OP_GREATERTHAN]:
                conditionallyEvaluateBtc(opGreaterThan),
            [OpcodesBTC.OP_LESSTHANOREQUAL]:
                conditionallyEvaluateBtc(opLessThanOrEqual),
            [OpcodesBTC.OP_GREATERTHANOREQUAL]:
                conditionallyEvaluateBtc(opGreaterThanOrEqual),
            [OpcodesBTC.OP_MIN]: conditionallyEvaluateBtc(opMin),
            [OpcodesBTC.OP_MAX]: conditionallyEvaluateBtc(opMax),
            [OpcodesBTC.OP_WITHIN]: conditionallyEvaluateBtc(opWithin),

            [OpcodesBTC.OP_RIPEMD160]: conditionallyEvaluateBtc(
                opRipemd160BtcLimits({ ripemd160 })
            ),
            [OpcodesBTC.OP_SHA1]: conditionallyEvaluateBtc(
                opSha1BtcLimits({ sha1 })
            ),
            [OpcodesBTC.OP_SHA256]: conditionallyEvaluateBtc(
                opSha256BtcLimits({ sha256 })
            ),
            [OpcodesBTC.OP_HASH160]: conditionallyEvaluateBtc(
                opHash160BtcLimits({ ripemd160, sha256 })
            ),
            [OpcodesBTC.OP_HASH256]: conditionallyEvaluateBtc(
                opHash256BtcLimits({ sha256 })
            ),
            [OpcodesBTC.OP_CODESEPARATOR]:
                conditionallyEvaluateBtc(opCodeSeparator),

            [OpcodesBTC.OP_CHECKSIG]: conditionallyEvaluateBtc(
                opCheckSigBtcLimits({ secp256k1, sha256 })
            ),
            [OpcodesBTC.OP_CHECKSIGVERIFY]: conditionallyEvaluateBtc(
                opCheckSigVerifyBtcLimits({ secp256k1, sha256 })
            ),
            [OpcodesBTC.OP_CHECKMULTISIG]: conditionallyEvaluateBtc(
                opCheckMultiSigBtcLimits({ secp256k1, sha256 })
            ),
            [OpcodesBTC.OP_CHECKMULTISIGVERIFY]: conditionallyEvaluateBtc(
                opCheckMultiSigVerifyBtcLimits({ secp256k1, sha256 })
            ),

            [OpcodesBTC.OP_CHECKLOCKTIMEVERIFY]:
                conditionallyEvaluateBtc(opCheckLockTimeVerify),
            [OpcodesBTC.OP_CHECKSEQUENCEVERIFY]:
                conditionallyEvaluateBtc(opCheckSequenceVerify),

            ...(standard
                ? {
                    [OpcodesBTC.OP_NOP1]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP4]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP5]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP6]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP7]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP8]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP9]: conditionallyEvaluateBtc(opNopDisallowed),
                    [OpcodesBTC.OP_NOP10]: conditionallyEvaluateBtc(opNopDisallowed)
                }
                : {
                    [OpcodesBTC.OP_NOP1]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP4]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP5]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP6]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP7]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP8]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP9]: conditionallyEvaluateBtc(opNop),
                    [OpcodesBTC.OP_NOP10]: conditionallyEvaluateBtc(opNop)
                })
        },

        success: (state) => {
            if (state.error !== undefined) return state.error;
            if (state.controlStack.length !== 0) return AuthenticationErrorCommon.nonEmptyControlStack;
            if (state.stack.length !== 1) return AuthenticationErrorCommon.requiresCleanStack;
            if (!stackItemIsTruthy(state.stack[0]!))
                return AuthenticationErrorCommon.unsuccessfulEvaluation;
            return true;
        },

        undefined: undefinedOperationBtc,

        verify: ({ sourceOutputs, transaction }, evaluate, stateSuccess) => {
            if (transaction.inputs.length === 0) return 'Transactions must have at least one input.';
            if (transaction.outputs.length === 0) return 'Transactions must have at least one output.';
            if (transaction.inputs.length !== sourceOutputs.length)
                return 'A spent output must be provided for each input.';

            const txSize = encodeTransactionBTC(transaction).length;
            if (txSize < ConsensusBTC.minimumTransactionSize)
                return `Transaction is ${txSize} B; minimum is ${ConsensusBTC.minimumTransactionSize}.`;
            if (txSize > ConsensusBTC.maximumTransactionSize)
                return `Transaction is ${txSize} B; exceeds ConsensusBTC.maximumTransactionSize.`;

            if (standard) {
                if (transaction.version < 1 || transaction.version > ConsensusBTC.maximumTransactionVersion)
                    return `Standard tx version must be 1–${ConsensusBTC.maximumTransactionVersion}.`;
                if (txSize > ConsensusBTC.maximumStandardTransactionSize)
                    return `Transaction exceeds standard size limit (${ConsensusBTC.maximumStandardTransactionSize}).`;

                for (const [i, output] of sourceOutputs.entries()) {
                    if (!isStandardOutputBytecode(output.lockingBytecode))
                        return `Input ${i} spends non-standard output.`;
                }

                let totalAdBytes = 0;
                for (const [i, out] of transaction.outputs.entries()) {
                    if (!isStandardOutputBytecode(out.lockingBytecode))
                        return `Output ${i} is non-standard.`;
                    if (isArbitraryDataOutput(out.lockingBytecode))
                        totalAdBytes += out.lockingBytecode.length + 1;
                }
                if (totalAdBytes > ConsensusBTC.maximumDataCarrierBytes)
                    return `Arbitrary-data outputs total ${totalAdBytes} B; limit is ${ConsensusBTC.maximumDataCarrierBytes}.`;

                for (const [i, inp] of transaction.inputs.entries()) {
                    const ulLen = inp.unlockingBytecode.length;
                    if (ulLen > ConsensusBTC.maximumStandardUnlockingBytecodeLength)
                        return `Input ${i} unlocking script is ${ulLen} B, exceeds standard limit ${ConsensusBTC.maximumStandardUnlockingBytecodeLength}.`;
                    if (!isPushOnly(inp.unlockingBytecode))
                        return `Input ${i} unlocking script must be push-only.`;
                }
            }

            for (const i of transaction.inputs.keys()) {
                const state = evaluate({ inputIndex: i, sourceOutputs, transaction });
                const res = stateSuccess(state);
                if (typeof res === 'string') return `Input ${i} failed: ${res}`;
            }
            return true;
        }
    };
};
