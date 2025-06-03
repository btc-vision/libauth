import type {
    AuthenticationInstruction,
    AuthenticationProgramCommon as AuthenticationProgramBTC,
    AuthenticationProgramCommon,
    AuthenticationProgramStateAlternateStack,
    AuthenticationProgramStateCodeSeparator,
    AuthenticationProgramStateControlStack,
    AuthenticationProgramStateError,
    AuthenticationProgramStateMinimum,
    AuthenticationProgramStateSignatureAnalysis,
    AuthenticationProgramStateStack,
    AuthenticationProgramStateTransactionContext,
    AuthenticationVirtualMachine,
    TransactionCommon as ResolvedTransactionBTC
} from '../../../../lib.js';
import { cloneAuthenticationInstruction, cloneAuthenticationProgramCommon, cloneStack } from '../../common/common.js';

export enum ConsensusBTC {

    maximumBytecodeLength = 10_000,

    maximumDataCarrierBytes = 223,

    maximumOperationCount = 201,

    maximumStackDepth = 1_000,

    maximumStackItemLength = 520,

    maximumVmNumberLength = 8,

    minVmNumber = '-9223372036854775807',

    maxVmNumber = '9223372036854775807',

    schnorrSignatureLength = 64,

    maximumStandardVersion = 2,

    maximumStandardUnlockingBytecodeLength = 1_650,

    minimumTransactionSize = 100,

    maximumStandardTransactionSize = 100_000,

    maximumTransactionSize = 1_000_000,

    maximumTransactionVersion = 2_147_483_647,

    maximumHashDigestIterations = 660,
}

export type AuthenticationProgramStateControlStackBTC =
    AuthenticationProgramStateControlStack<boolean | number>;

export type AuthenticationProgramStateResourceLimitsBTC = {

    hashDigestIterations: number;
};

export type AuthenticationProgramStateBTC =
    AuthenticationProgramStateAlternateStack &
    AuthenticationProgramStateCodeSeparator &
    AuthenticationProgramStateControlStackBTC &
    AuthenticationProgramStateError &
    AuthenticationProgramStateMinimum &
    AuthenticationProgramStateResourceLimitsBTC &
    AuthenticationProgramStateSignatureAnalysis &
    AuthenticationProgramStateStack &
    AuthenticationProgramStateTransactionContext;

export type AuthenticationVirtualMachineBTC = AuthenticationVirtualMachine<
    ResolvedTransactionBTC,
    AuthenticationProgramBTC,
    AuthenticationProgramStateBTC
>;

export const cloneAuthenticationProgramStateBTC = <
    State extends AuthenticationProgramStateBTC,
>(
    state: State
) => ({
    ...(state.error === undefined ? {} : { error: state.error }),
    alternateStack: cloneStack(state.alternateStack),
    controlStack: state.controlStack.slice(),
    hashDigestIterations: state.hashDigestIterations,
    instructions: state.instructions.map(cloneAuthenticationInstruction),
    ip: state.ip,
    lastCodeSeparator: state.lastCodeSeparator,
    program: cloneAuthenticationProgramCommon(state.program),
    signedMessages: state.signedMessages.map((m) => ({
        digest: m.digest.slice(),
        ...('serialization' in m
            ? { serialization: m.serialization.slice() }
            : { message: m.message.slice() })
    })),
    stack: cloneStack(state.stack)
});

export const createAuthenticationProgramStateBTC = ({
                                                        program,
                                                        instructions,
                                                        stack
                                                    }: {
    program: AuthenticationProgramCommon;
    instructions: AuthenticationInstruction[];
    stack: Uint8Array[];
}): AuthenticationProgramStateBTC => ({
    alternateStack: [],
    controlStack: [],
    hashDigestIterations: 0,
    instructions,
    ip: 0,
    lastCodeSeparator: -1,
    program,
    signedMessages: [],
    stack
});
