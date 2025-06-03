import type {
    AuthenticationInstructionPush,
    AuthenticationProgramStateControlStackBTC,
    AuthenticationProgramStateError,
    AuthenticationProgramStateMinimum,
    AuthenticationProgramStateStack,
    Operation
} from '../../../../lib.js';

import {
    applyError,
    AuthenticationErrorCommon,
    ConsensusCommon,
    isMinimalDataPush,
    pushToStack,
    stackItemIsTruthy,
    useOneStackItem
} from '../../common/common.js';

const executionIsActive = <
    State extends AuthenticationProgramStateControlStackBTC,
>(
    state: State
) => state.controlStack.every((item) => item !== false);

export const conditionallyEvaluateBtc = <
    State extends AuthenticationProgramStateControlStackBTC,
>(
    operation: Operation<State>
): Operation<State> => (state) =>
    executionIsActive(state) ? operation(state) : state;

export const undefinedOperationBtc = conditionallyEvaluateBtc(
    <
        State extends AuthenticationProgramStateControlStackBTC &
            AuthenticationProgramStateError,
    >(
        state: State
    ) => applyError(state, AuthenticationErrorCommon.unknownOpcode)
);

export const pushOperationBtc =
    <
        State extends AuthenticationProgramStateControlStackBTC &
            AuthenticationProgramStateError &
            AuthenticationProgramStateMinimum &
            AuthenticationProgramStateStack,
    >(
        maximumPushSize = ConsensusCommon.maximumStackItemLength as number
    ): Operation<State> =>
        (state) => {
            const instruction = state.instructions[
                state.ip
                ] as AuthenticationInstructionPush;

            return instruction.data.length > maximumPushSize
                ? applyError(
                    state,
                    `${AuthenticationErrorCommon.exceededMaximumStackItemLength} Item length: ${instruction.data.length} bytes.`
                )
                : executionIsActive(state)
                    ? isMinimalDataPush(instruction.opcode, instruction.data)
                        ? pushToStack(state, instruction.data)
                        : applyError(state, AuthenticationErrorCommon.nonMinimalPush)
                    : state;
        };

export const pushToControlStackBtc = <
    State extends AuthenticationProgramStateControlStackBTC,
>(
    state: State,
    value: boolean
) => {

    state.controlStack.push(value);
    return state;
};

export const opIfBtc = <
    State extends AuthenticationProgramStateControlStackBTC &
        AuthenticationProgramStateError &
        AuthenticationProgramStateStack,
>(
    state: State
) =>
    executionIsActive(state)
        ? useOneStackItem(state, (next, [item]) =>
            pushToControlStackBtc(next, stackItemIsTruthy(item))
        )
        : pushToControlStackBtc(state, false);

export const opNotIfBtc = <
    State extends AuthenticationProgramStateControlStackBTC &
        AuthenticationProgramStateError &
        AuthenticationProgramStateStack,
>(
    state: State
) =>
    executionIsActive(state)
        ? useOneStackItem(state, (next, [item]) =>
            pushToControlStackBtc(next, !stackItemIsTruthy(item))
        )
        : pushToControlStackBtc(state, false);

export const opEndIfBtc = <
    State extends AuthenticationProgramStateControlStackBTC &
        AuthenticationProgramStateError,
>(
    state: State
) => {

    const element = state.controlStack.pop();
    return typeof element !== 'boolean'
        ? applyError(state, AuthenticationErrorCommon.unexpectedEndIf)
        : state;
};

export const opElseBtc = <
    State extends AuthenticationProgramStateControlStackBTC &
        AuthenticationProgramStateError,
>(
    state: State
) => {
    const top = state.controlStack[state.controlStack.length - 1];
    if (typeof top !== 'boolean') {
        return applyError(state, AuthenticationErrorCommon.unexpectedElse);
    }

    state.controlStack[state.controlStack.length - 1] = !top;
    return state;
};

