import idautils
import ida_funcs
import idaapi
import idc

NAME_WIDTH = 35
API_WIDTH = 60

def is_valid_func(func_ea):
    flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
    if flags & ida_funcs.FUNC_THUNK or flags & ida_funcs.FUNC_LIB:
        return False
    return True

def is_direct_call(ref):
    return (
        idc.print_insn_mnem(ref) == "call" and
        idc.get_operand_type(ref, 0) == idc.o_near
    )

def get_basic_block_count(func_ea):
    func = idaapi.get_func(func_ea)
    if not func:
        return 0
    flowchart = idaapi.FlowChart(func)
    try:
        return flowchart.size()
    except TypeError:
        return flowchart.size

def extract_apis(func_ea):
    api_calls = set()
    for insn_ea in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(insn_ea) != "call":
            continue
        op_type = idc.get_operand_type(insn_ea, 0)
        # direct calls
        if op_type in (idc.o_mem, idc.o_near):
            addr = idc.get_operand_value(insn_ea, 0)
            name = idc.get_name(addr, idc.GN_VISIBLE)
            if name:
                api_calls.add(name)
        # indirect calls
        elif op_type == idc.o_reg:
            for xref in idautils.CodeRefsFrom(insn_ea, 0):
                name = idc.get_name(xref, idc.GN_VISIBLE)
                if name:
                    api_calls.add(name)
    return sorted(api_calls)

def score_zero_xref(func_ea, apis):
    score = 0
    bb_count = get_basic_block_count(func_ea)
    score += bb_count * 2
    for api in apis:
        if not (api.startswith("__") or api.startswith("___") or
                "crt" in api or "SEH" in api or "guard" in api or
                api.startswith("?") or "unknown_libname" in api):
            score += 3
        elif api.startswith("sub_"):
            score += 2
    return score

def is_interesting_zero_func(func_ea, apis):
    name = ida_funcs.get_func_name(func_ea)
    # skip boilerplate
    if name.startswith("__") or name.startswith("___") or "crt" in name:
        return False
    score = score_zero_xref(func_ea, apis)
    return score > 5  # threshold

def wrap_api_list(api_list, width):
    if not api_list:
        return ["None"]
    lines = []
    current = ""
    for api in api_list:
        if len(current) + len(api) + (2 if current else 0) <= width:
            current = (current + ", " + api) if current else api
        else:
            lines.append(current)
            current = api
    if current:
        lines.append(current)
    return lines

def print_header(title):
    print("\n" + "=" * 120)
    print(title)
    print("=" * 120)
    print("{:<12} {:<{nw}} {:<10} {:<8} {:<6} {}".format(
        "Address", "Function", "Xrefs", "BBs", "Score", "APIs",
        nw=NAME_WIDTH
    ))
    print("-" * 120)

def main():
    referenced = []
    zero_xref = []

    for func_ea in idautils.Functions():
        if not is_valid_func(func_ea):
            continue
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        func_name = ida_funcs.get_func_name(func_ea)
        bb_count = get_basic_block_count(func_ea)
        apis = extract_apis(func_ea)

        xref_count = 0
        for ref in idautils.CodeRefsTo(func_ea, 0):
            if not is_direct_call(ref):
                continue
            caller = ida_funcs.get_func(ref)
            if not caller:
                continue
            if not is_valid_func(caller.start_ea):
                continue
            if (caller.end_ea - caller.start_ea) < 20:
                continue
            xref_count += 1

        score = (xref_count * 3) + (bb_count * 2) + len(apis)

        if xref_count == 0:
            if is_interesting_zero_func(func_ea, apis):
                zero_xref.append((func_ea, func_name, apis, bb_count, score))
        else:
            referenced.append((xref_count, func_ea, func_name, apis, bb_count, score))

    referenced.sort(key=lambda x: x[5], reverse=True)
    zero_xref.sort(key=lambda x: x[4], reverse=True)

    print_header("[+] REFERENCED FUNCTIONS")
    for count, ea, name, apis, bb, score in referenced:
        api_lines = wrap_api_list(apis, API_WIDTH)
        print("0x{:08X} {:<{nw}} {:<10} {:<8} {:<6} {}".format(
            ea, name[:NAME_WIDTH], count, bb, score, api_lines[0], nw=NAME_WIDTH
        ))
        for line in api_lines[1:]:
            print("{:<12} {:<{nw}} {:<10} {:<8} {:<6} {}".format(
                "", "", "", "", "", line, nw=NAME_WIDTH
            ))

    print_header("[+] ZERO-XREF FUNCTIONS (HEURISTIC)")
    for ea, name, apis, bb, score in zero_xref:
        api_lines = wrap_api_list(apis, API_WIDTH)
        print("0x{:08X} {:<{nw}} {:<10} {:<8} {:<6} {}".format(
            ea, name[:NAME_WIDTH], 0, bb, score, api_lines[0], nw=NAME_WIDTH
        ))
        for line in api_lines[1:]:
            print("{:<12} {:<{nw}} {:<10} {:<8} {:<6} {}".format(
                "", "", "", "", "", line, nw=NAME_WIDTH
            ))

if __name__ == "__main__":
    main()
