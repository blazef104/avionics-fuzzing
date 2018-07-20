"""
    unicorn_template.py

    Create a template for afl unicorn using current context

    Based on the template provided by Nathan Voss <njvoss299@gmail.com>
    in the afl-unicorn repository
     
    2018 Giulio Ginesi
"""

# GDB Python SDK
import gdb

# ---------------------------
# ---- From unicorn_dumper.py


def map_arch():
    arch = get_arch()  # from GEF
    if 'x86_64' in arch or 'x86-64' in arch:
        return "x64"
    elif 'x86' in arch or 'i386' in arch:
        return "x86"
    elif 'aarch64' in arch or 'arm64' in arch:
        return "arm64_const"
    elif 'aarch64_be' in arch:
        return "arm64eb_const"
    elif 'armeb' in arch:
        return "armeb_const"
    elif 'arm' in arch:
        return "arm_const"
    else:
        raise NameError("Can't find arch")

# ---------------------------

def skip_function(func):
    res = ""
    for f in func:
        address = long(gdb.parse_and_eval(f).address)
        res+="(address == 0x{:x}) or ".format(address)
    return res[:-4]

def infos():
    args = gdb.execute("info args", to_string=True).split("\n")
    if len(args) >= 3:
        a = args[0].split(" ")[-1]
        a1 = args[1].split(" ")[-1]
        print("Using {} and {} as best guess for the arguments of the function".format(a, a1))
        return a, a1
    else:
        print("Can't determine right args for this function")
        return "", ""

def get_end(addr):
    inst = gef_disassemble(addr, 15)
    for i in inst:
        if i.mnemo == "pop":
            for op in i.operands:
                if (op == " pc") or (op == " pc}"):
                    print("0x{0:x} {1}, {2}".format(i.address, i.mnemo, i.operands))
                    print("Setting 0x{:x} as best guess for end of the function".format(i.address))
                    return i.address
    return get_end(addr+15)


def gen_file(arch, start, end, arg0, arg1, sk):
    print(end)
    return("""
import argparse
from unicorn import *
from unicorn.{0} import *  # TODO: Set correct architecture here as necessary

import unicorn_loader_vuln as unicorn_loader

# Simple stand-in heap to prevent OS/kernel issues
unicorn_heap = None

# Start and end address of emulation
START_ADDRESS = 0x{1:x}
END_ADDRESS   = 0x{2:x}
BUFFER_ADDR   = {3} # TODO: set this manually!
DATA_SIZE_MAX = {4} # TODO: set this manually!
      
def unicorn_hook_instruction(uc, address, size, user_data):
    if {5}:
        print("skipping one of the chosen functions")
        previous_pc = uc.reg_read(UC_ARM_REG_PC)
        ret_addr = uc.reg_read(UC_ARM_REG_LR)
        uc.reg_write(UC_ARM_REG_PC, ret_addr)
""".format(arch, start, end, arg0, arg1, sk)+
"""
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('context_dir', type=str, help="Directory containing process context")
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input content")
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Dump trace info")
    args = parser.parse_args()

    print('Loading context from {}'.format(args.context_dir))
    uc = unicorn_loader.AflUnicornEngine(args.context_dir, enable_trace=args.debug, debug_print=True)

    # Instantiate the hook function to avoid emulation errors
    global unicorn_heap
    unicorn_heap = unicorn_loader.UnicornSimpleHeap(uc, debug_print=True)
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
      """)


def main():
    functions_to_skip = ["putchar", "printf", "fflush", "puts", "addRecentlySeenICAOAddr"]
    try:
        GEF_TEST = set_arch()
    except Exception as e:
        print("!!! GEF not running in GDB.  Please run gef.py by executing:")
        print('\tpython execfile ("<path_to_gef>/gef.py")')
        return
    
    arch = map_arch()
    start = get_register("pc")
    end_addr = get_end(start)
    print(end_addr)
    # info args commaind in gdb will probably help to find the buffer and his size, 
    # i have to find how to invoke it in python
    for el in get_process_maps():
        if el.path == "[heap]":
            heapStart = el.page_start
            heapEnd = heapStart+el.size
    print("HEAP ADDRESSES: 0x{0:x} 0x{1:x}".format(heapStart, heapEnd))
    print("Put those in your unicorn_loader.py")
    sk = skip_function(functions_to_skip)
    arg0, arg1 = infos()
    current_loaded = (gdb.objfiles()[0].filename.split("/")[-1])
    filename = "test_"+current_loaded+".py"
    final = open(filename, "w+")
    final.write(gen_file(arch,start,end_addr,arg0,arg1,sk))
    final.close()
    print("{} generated!".format(filename))

if __name__ == "__main__":
    main()


