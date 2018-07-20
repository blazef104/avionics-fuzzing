
import argparse
from unicorn import *
from unicorn.arm_const import *  # TODO: Set correct architecture here as necessary

import unicorn_loader_vuln as unicorn_loader

# Simple stand-in heap to prevent OS/kernel issues
unicorn_heap = None

# Start and end address of emulation
START_ADDRESS = 0x15aac
END_ADDRESS   = 0x15bb0
BUFFER_ADDR   = 0x76c6a008 # TODO: set this manually!
DATA_SIZE_MAX = 0x200ee # TODO: set this manually!

def unicorn_hook_instruction(uc, address, size, user_data):
    if (address == 0x11540) or (address == 0x11538) or (address == 0x117b4) or (address == 0x11560) or (address == 0x115b0) or (address == 0x116b8) or (address == 0x13184):
        print("skipping one of the chosen functions")
        previous_pc = uc.reg_read(UC_ARM_REG_PC)
        ret_addr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_PC, ret_addr)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('context_dir', type=str, help="Directory containing process context")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input content")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Dump trace info")
    args = parser.parse_args()

    print('Loading context from {}'.format(args.context_dir))
    uc = unicorn_loader.AflUnicornEngine(args.context_dir, enable_trace=args.debug, debug_print=args.debug)

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
    print("Allocated mutated input buffer @ 0x{0:016x}".format(BUFFER_ADDR))
    uc.mem_write(BUFFER_ADDR, input_content)

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
