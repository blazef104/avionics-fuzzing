"""
    template_test_harness.py

    Template which loads the context of a process into a Unicorn Engine,
    instance, loads a custom (mutated) inputs, and executes the
    desired code. Designed to be used in conjunction with one of the
    Unicorn Context Dumper scripts.

    Author:
        Nathan Voss <njvoss299@gmail.com>
"""

import argparse

from unicorn import *
from unicorn.arm_const import *  # TODO: Set correct architecture here as necessary

import unicorn_loader_detectModeS as unicorn_loader

# Simple stand-in heap to prevent OS/kernel issues
unicorn_heap = None

# Start and end address of emulation
START_ADDRESS = 0xd980 # 0xD980 # TODO: Set start address here
END_ADDRESS   = 0xda18 #0xdfe8 # TODO: Set end address here
BUFFER_ADDR   = 0x76c6a008
DATA_SIZE_MAX = 0x401dc # 1090_samll.bin length
"""
    Implement target-specific hooks in here.
    Stub out, skip past, and re-implement necessary functionality as appropriate
"""
def unicorn_hook_instruction(uc, address, size, user_data):

    # TODO: Setup hooks and handle anything you need to here
    #    - For example, hook malloc/free/etc. and handle it internally

#    print("Infos: \n\t-Address: {0:x}\n\t-Size: {1}\n\t-User Data: {2}".format(address, size, user_data))

    # if (address == 0xbb88):
    #     print("displayModesMessage, skipping")
    #     previous_pc = uc.reg_read(UC_ARM_REG_PC)
    #     ret_addr = uc.reg_read(UC_ARM_REG_LR)
    #     print("Previous PC = {0:x} Next = {1:x}".format(previous_pc, ret_addr))
    #     uc.reg_write(UC_ARM_REG_PC, ret_addr)
        #raw_input()
    if (address == 0x9a40) or (address == 0x97c4) or (address == 0x97e8) or (address == 0x9944) :
        print("putchar, printf, fflush or puts , skipping")
        previous_pc = uc.reg_read(UC_ARM_REG_PC)
        ret_addr = uc.reg_read(UC_ARM_REG_LR)
        print("Previous PC = 0x{0:x} Next = 0x{1:x}".format(previous_pc, ret_addr))
        uc.reg_write(UC_ARM_REG_PC, ret_addr)
        #raw_input()
    if (address == 0xb228):
        print("addRecentlySeenICAOMessage, skipping")
        previous_pc = uc.reg_read(UC_ARM_REG_PC)
        ret_addr = uc.reg_read(UC_ARM_REG_LR)
        print("Previous PC = 0x{0:x} Next = 0x{1:x}".format(previous_pc, ret_addr))
        uc.reg_write(UC_ARM_REG_PC, ret_addr)
        #raw_input()


#------------------------
#---- Main test function

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('context_dir', type=str, help="Directory containing process context")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input content")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Dump trace info")
    args = parser.parse_args()

    print("Loading context from {}".format(args.context_dir))
    uc = unicorn_loader.AflUnicornEngine(args.context_dir, enable_trace=args.debug, debug_print=False)

    # Instantiate the hook function to avoid emulation errors
    global unicorn_heap
    unicorn_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=False)
    uc.hook_add(UC_HOOK_CODE, unicorn_hook_instruction)

    # Execute 1 instruction just to startup the forkserver
    # NOTE: This instruction will be executed again later, so be sure that
    #       there are no negative consequences to the overall execution state.
    #       If there are, change the later call to emu_start to no re-execute
    #       the first instruction.

    print("Starting the forkserver by executing 1 instruction")
    try:
        uc.emu_start(START_ADDRESS, 0, 0, count=1)
    except UcError as e:
        print("ERROR: Failed to execute a single instruction (error: {})!".format(e))
        return

    #our buffer is located at 0x76c7a008 the data from 1090_small.bin start
    # to make sense from 0x76c6a1e4. The file length is 0x401dc = 262620

    # Allocate a buffer and load a mutated input and put it into the right spot
    if args.input_file:
        print("Loading input content from {}".format(args.input_file))
        input_file = open(args.input_file, 'rb')
        input_content = input_file.read()
        input_file.close()

    # Apply constraints to the mutated input
    if len(input_content) > DATA_SIZE_MAX:
        print("Test input is too long (> {} bytes)".format(DATA_SIZE_MAX))
        return
    #     raise exceptions.NotImplementedError('No constraints on the mutated inputs have been set!')

    #     # Allocate a new buffer and put the input into it

    # print("Before:")
    # for cont in uc.mem_read(BUFFER_ADDR, 1000):
    #     print("0x{:x}".format(cont))
    print("Allocated mutated input buffer @ 0x{0:016x}".format(BUFFER_ADDR))
    uc.mem_write(BUFFER_ADDR, input_content)
    # print("After:")
    # for cont in uc.mem_read(BUFFER_ADDR, 1000):
    #     print("0x{:x}".format(cont))
    # raw_input()

    # Run the test
    print("Executing from 0x{0:016x} to 0x{1:016x}".format(START_ADDRESS, END_ADDRESS))
    try:
        result = uc.emu_start(START_ADDRESS, END_ADDRESS, timeout=0, count=0)
    except UcError as e:
        # If something went wrong during emulation a signal is raised to force this
        # script to crash in a way that AFL can detect ('uc.force_crash()' should be
        # called for any condition that you want AFL to treat as a crash).
        print("Execution failed with error: {}".format(e))
        uc.dump_regs()
        uc.force_crash(e)

    print("Final register state:")
    uc.dump_regs()

    print("Done.")

if __name__ == "__main__":
    main()
