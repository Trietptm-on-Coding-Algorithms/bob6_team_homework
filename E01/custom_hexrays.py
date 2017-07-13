from idaapi import *
import re


''' Basic class for hexrays in 64bit binary

Init - Set reginster default value.

GetRegValue(reg) - Get specipic register's value.

SetRegValue(reg, value) - Set specipic register's value.

ResetRegValue() - Reset a function's arguments.

GetFuncArgs() - Get function's arguments.

CheckFuncArgs(opr) - Checking for function's operand.

'''
register_maps = ['rax', 'eax', 'rdi', 'rsi', 'r8', 'rdx', 'rcx', 'r9', 'edi', 'esi', 'edx', 'ecx']
class register:
    def __init__(self):
        for reg in register_maps:
            exec('self.{} = \"\"'.format(reg))

    def GetRegValue(self, reg):
        if reg in register_maps:
            tmp = eval('self.{}'.format(reg))
            return tmp
        else:
            return reg

    def SetRegValue(self, reg, value):
        if reg in register_maps:
            exec('self.{} = \"{}\"'.format(reg, value))
        else:
            pass

    def ResetRegValue(self):
        for reg in register_maps[2:]:
            exec('self.{} = \"\"'.format(reg))

    def GetFuncArgs(self):
        choice_reg_value = lambda *args : [arg if arg else '' for arg in args ][0]
        convert = lambda x : repr(x.strip('\'')) if '\\' in repr(x) else x
        arg_list = [
                choice_reg_value(self.edi, self.rdi),
                choice_reg_value(self.esi, self.rsi),
                choice_reg_value(self.edx, self.rdx),
                choice_reg_value(self.ecx, self.rcx),
                choice_reg_value(self.r8),
                choice_reg_value(self.r9)
                ]
        result = ', '.join([convert(tmp) for tmp in arg_list if tmp])
        return result

    def CheckFuncArgs(self, opr):
        if opr in register_maps[2:]:
            return True
        else:
            return False

''' Get functions list

After obtaining the start address and end address of the function, use that address to obtain the function address.

'''
def GetFuncList():
    address = here()

    start_seg = SegStart(address)
    end_seg = SegEnd(address)

    index = 0
    FuncList = []
    for x in Functions(start_seg, end_seg):
        FuncList.append(x)
        index += 1

    return FuncList


''' Main processing function for x64 binary Hexrays.


This function is the main function that functions as a hexray for 64bit binaries.

The first step is to divide the assembly code into instructions and operands.

After that, different routines are executed according to each instruction.

'''
def HexRay64(address):
    # Routine of Initializing local varibles.
    re_find = lambda opr: re.findall(r"var_([0-9a-fA-F]+)\]", opr)
    convert = lambda x : repr(x.strip('\'')) if '\\' in repr(x) else x
    source = ""
    pre_process = ""
    ret_type = ""
    name = ""
    arg = ""
    block = ""
    start = 0
    index = 0
    after_call = 0
    ret_type = "int "

    r = register()
    name = GetFunctionName(address)

    # Processing all Instructions Address
    for line in FuncItems(address):
        # Separate a asm(instruction, operand)
        ins = GetMnem(line)
        opr1 = GetOpnd(line, 0)
        opr2 = GetOpnd(line, 1)

        # Prologue check
        if ins == "mov":
            if len(re_find(opr1)) != 0:
                start = line
                break
        else:
            continue
    
    # Processing all Instructions Address
    for line in FuncItems(address):
        if line < start:
            continue

        # Separate a asm(instruction, operand)
        ins = GetMnem(line)
        opr1 = GetOpnd(line, 0)
        opr2 = GetOpnd(line, 1)

        temp = []
        flag = ""
        
        
        '''

        Routine of Processing 'mov' instruction.
        
        There are several cases to get the operands of 'mov' instruction.

        syntax )
             mov <reg>,<reg>
             mov <reg>,<mem>
             mov <mem>,<reg>
             mov <reg>,<const>
             mov <mem>,<const>

        '''
        if ins =e "mov":
            # Current function's arguments setting
            if len(re_find(opr1)) != 0 and r.CheckFuncArgs(opr2):
                if index != 0:
                    arg += ", "
                arg += "int a{0}".format(index + 1)
                r.SetRegValue(opr2, "a" + str(index+1))
                index += 1

            # Processing operand1
            temp = re_find(opr1)
            if len(temp) == 0:              # opr1 = Register
                flag = opr1
            else:                           # opr1 = memory address
                pre = "#define v{0} [rbp-var_{1}]\n".format(temp[0], temp[0])
                if pre_process.find(pre) == -1:
                    pre_process += pre
                    block += "\tint "
                else:
                    block += "\t"
                temp = re_find(opr1)
                block += "v{0} = ".format(temp[0])

            # Processing operand2
            temp = re_find(opr2)
            if len(temp) == 0:                  # opr2 = register or value
                opr2 = r.GetRegValue(opr2)      # Find operand2's type
                if opr2.find("offset") != -1:
                    opr2 = repr(str(GetString(GetOperandValue(line, 1))))
                if flag != "":                  # opr1 = Register
                    if after_call == 1:
                        block += "\t" + r.eax + ";\n"
                    r.SetRegValue(flag, opr2)
                else:
                    if after_call == 1:         # use a return value
                        block += r.eax + ";\n"
                    else:
                        block += "{0};\n".format(opr2)
            else:                               # opr2 = memory
                pre = "#define v{0} [rbp-var_{1}]\n".format(temp[0], temp[0])
                if pre_process.find(pre) == -1:
                    pre_process += pre
                if flag != "":
                    r.SetRegValue(flag, "v" + temp[0])
                else:
                    temp = re_find(opr2)
                    block += "v{0};\n".format(temp[0])

        '''

        Routine of Processing 'imul' instruction.
        
        There are several cases to get the operands of 'imul' instruction.
        
        syntax )
            imul <reg32>,<reg32>
            imul <reg32>,<mem>
            imul <reg32>,<reg32>,<con>
            imul <reg32>,<mem>,<con>
        
        '''
        if ins == "imul":
            temp = re_find(opr1)
            if len(temp) == 0:  # opr1 = Register
                flag = opr1
            else:               # opr1 = memory address
                block += "\t"
                temp = re_find(opr1)
                block += "v{0} = ".format(temp[0])

            temp = re_find(opr2)
            if len(temp) == 0:  # opr2 = register or constant
                opr2 = r.GetRegValue(opr2)
                if flag != "":
                    if after_call == 1:
                        block += "\t" + r.eax + ";\n"
                    r.SetRegValue(flag, r.eax + " * " +opr2)
                else:
                    block += r.eax + "* {0};\n".format(opr2)
            else:               # opr2 = memory
                if flag != "":
                    r.SetRegValue(flag, r.eax + " * v" + temp[0])
                else:
                    temp = re_find(opr2)
                    block += r.eax + "* v{0};\n".format(temp[0])

        '''

        Routine of Processing 'add' instruction.
        
        There are several cases to get the operands of 'add' instruction.
        
        syntax )
            add <reg>,<reg>
            add <reg>,<mem>
            add <mem>,<reg>
            add <reg>,<con>
            add <mem>,<con>
        
        '''
        if ins == "add":
            temp = re_find(opr1)
            if len(temp) == 0:  # opr1 = Register
                flag = opr1
            else:               # opr1 = memory address
                block += "\t"
                temp = re_find(opr1)
                block += "v{0} = ".format(temp[0])
                val_num = int(temp[0])

            temp = re_find(opr2)
            if len(temp) == 0:  # opr2 = register or constant
                opr2 = r.GetRegValue(opr2)
                if flag != "":
                    if after_call == 1:
                        block += "\t" + r.eax + ";\n"
                    r.SetRegValue(flag, r.GetRegValue(opr1) + " + " +opr2)
                else:
                    block += "v{0} + {1};\n".format(val_num, opr2)
            else:               # opr2 = memory
                if flag != "":
                    r.SetRegValue(flag, r.GetRegValue(opr1) + " + v" + temp[0])
                else:
                    temp = re_find(opr2)
                    block += "v{0} + v{1};\n".format(val_num, temp[0])


        '''

        Routine of Processing 'call' instruction.
        
        Finding calling function and that function's arguments and find return value.

        '''
        if ins == "call":
            r.eax = opr1 + "(" + r.GetFuncArgs() +")"   # for return a value
            r.ResetRegValue()
            after_call = 1  # for return a value
            continue
        
        
        '''

        Routine of Processing return value.

        Detect 'leave' or 'pop rbp' instructions, and find return value using eax register.

        '''
        # processing leave asm
        if ins == "leave":
            block += "\n\treturn " + r.eax + ";\n"
            break
        # processing pop rbp asm
        if ins == "pop" and opr1 == "rbp":
            block += "\n\treturn " + r.eax + ";\n"
            break

        after_call = 0      # before asm is not "call;", so reset

    source += ret_type 
    source += name 
    source += "({0})\n".format(arg)
    source += "{\n " + block + "}\n\n"
    return source.replace('\'', '\"')


''' Main processing function for i386 binary Hexrays.

This function is the main function that functions as a hexray for i386 binaries.

The first step is to divide the assembly code into instructions and operands.

After that, different routines are executed according to each instruction.

'''
def HexRay32(hexray):
    index_search = lambda s, s2 : s2.index(s) if s in s2 else -1 
    asm = ""
    reg = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']
    reg2 = ['a', 'b', 'c', 'd']
    tmp = ['', '', '', '', '', '', '', '', '', '', '', '', '', '', '']
    push_tmp = []
    source = ""

    prologue = 0
    check = 0
    arg_count = 0
    source += "int " + GetFunctionName(hexray) + "()\n{\n"
    for h in FuncItems(hexray):
        check = 0
        if "xor     eax, eax" == GetDisasm(h):
            prologue = 1
            continue
        elif prologue == 0:
            continue
       
        if GetDisasm(h).find("[ebp+var_C]") > 0:
            source += "\treturn " + str(tmp[0])+";\n" 
            break
       
        ins = GetMnem(h)
        op1 = GetOpnd(h, 0)
        op2 = GetOpnd(h, 1)

        '''

        Routine of Processing 'mov' instruction.
        
        There are several cases to get the operands of 'mov' instruction.

        syntax )
             mov <reg>,<reg>
             mov <reg>,<mem>
             mov <mem>,<reg>
             mov <reg>,<const>
             mov <mem>,<const>

        '''
        if "mov" == ins:
            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
                pass
            else: 
                op1 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op1)

            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
                pass
            else:
                op2 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op2)

            if index_search(op2,reg) >= 0:    # if op2 reg
                check = 1
                if op1[0].find("var_") >= 0:
                    source += "\tint " + str(op1[0]) + "= " + str(tmp[index_search(op2,reg)])+";\n"

            if index_search(op1, reg) >= 0:     # if op1 reg
                if op2[0].find("var_") >= 0:
                    tmp[index_search(op1,reg)] = str(op2[0])
                    continue
                if check == 1:              # op2 check 
                    pass
                else:
                    if op2.find("h") >= 0:
                        op2 = op2.split('h')[0]
                        tmp[index_search(op1,reg)] = str(int(op2,16))
                        continue
                    else:
                        if unicode(op2).isnumeric():
                            tmp[index_search(op1,reg)] = str(op2)
                            continue

                if index_search(op2,reg) >=0:
                    tmp[index_search(op1,reg)] = tmp[index_search(op2,reg)]
                    continue

                if index_search(op2[1:4],reg) >= 0:
                    if len(op2) <= 5:
                        tmp[index_search(op1,reg)] = "*("+str(tmp[index_search(op2[1:4],reg)])+")" 


            if op1[0].find("var_") >= 0:   # if op1 var 
                if check == 1:
                    pass
                else:          
                    if op2.find("h") >= 0:
                        op2 = op2.split('h')[0]
                        source += "\tint " + op1[0]+"="+ str(int(op2,16))+";\n"
                    else:
                        if unicode(op2).isnumeric():
                            source += "\tint " + op1[0]+"="+ str(op2)+";\n"


        '''

        Routine of Processing 'lea' instruction.
        
        There are severals case to get the operands of 'lea' instruction.
        
        syntax )
            lea <reg32>,<mem>

        '''
        if "lea" == ins:
            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
                pass
            else:
                op2 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op2)
                if index_search(op1,reg) >= 0:
                    tmp[index_search(op1,reg)] = "&"+str(op2[0])
                    continue

            if index_search(op1,reg) >= 0:
                op2_reg = op2[1:4]
                op2_num = op2[5:-1]
                op2_o   = op2[4:5]
                tmp[index_search(op1,reg)] = str(tmp[index_search(op2_reg,reg)]) + str(op2_o) + str(int(op2_num)/4) 


        '''

        Routine of Processing 'xor' instruction.
        
        There are severals case to get the operands of 'xor' instruction.
        
        syntax )
            xor <reg>,<reg>
            xor <reg>,<mem>
            xor <mem>,<reg>
            xor <reg>,<con>
            xor <mem>,<con>

        '''
        if "xor" == ins:
            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
                pass
            else: 
                op1 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op1)

            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
                pass
            else:
                op2 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op2)

            if index_search(op2,reg) >= 0:
                if op1[0].find("var_") >= 0:
                    source += "\t"+str(op1[0]) + " ^= " + str(tmp[index_search(op2,reg)])+";\n"
                if index_search(op1,reg) >= 0:
                    tmp[index_search(op1,reg)] = str(tmp[index_search(op2,reg)])+ "^(" + str(tmp[index_search(op1,reg)]) + ")"  


        '''

        Routine of Processing 'sub' instruction.
        
        There are severals case to get the operands of 'sub' instruction.
        
        syntax )
            sub <reg>,<reg>
            sub <reg>,<mem>
            sub <mem>,<reg>
            sub <reg>,<con>
            sub <mem>,<con>

        '''
        if "sub" == ins:
            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
                pass
            else: 
                op1 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op1)

            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
                pass
            else:
                op2 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op2)


        '''

        Routine of Processing 'add' instruction.
        
        There are several cases to get the operands of 'add' instruction.
        
        syntax )
            add <reg>,<reg>
            add <reg>,<mem>
            add <mem>,<reg>
            add <reg>,<con>
            add <mem>,<con>
        
        '''
        if "add" == ins:
            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
                pass
            else: 
                op1 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op1)

            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op2) == []:
                pass
            else:
                op2 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op2)

            if index_search(op1,reg) >= 0:
                if index_search(op2,reg) >=0:
                    tmp[index_search(op1,reg)] = str(tmp[index_search(op1,reg)]) + str(tmp[index_search(op2,reg)])

                if op2.find("h") >= 0:
                    op2 = op2.split('h')[0]
                    tmp[index_search(op1,reg)] += "+" + str(int(op2,16)/4)
                    continue
                else:
                    if unicode(op2).isnumeric():
                        tmp[index_search(op1,reg)] += "+" + str(int(op2)/4)
                        continue   


        '''

        Routine of Processing 'push' instruction.
        
        This routine is that save function's arguments. 

        '''
        if "push" == ins:
            if re.findall(r"var_[(0-9a-fA-F)]{1,}",op1) == []:
                if index_search(op1,reg) >=0:
                    push_tmp.append(tmp[index_search(op1,reg)])
                else:
                    if "offset" in op1:
                        text = str(GetString(GetOperandValue(h, 0)))
                        push_tmp.append(repr(text))
            else: 
                op1 = re.findall(r"var_[(0-9a-fA-F)]{1,}",op1)
                push_tmp.append('&' + str(op1[0]))
             

        '''

        Routine of Processing 'call' instruction.
        
        Finding calling function and that function's arguments and find return value.

        '''
        if "call" == ins:
            op1 = op1.split("_")[-1]
            source += "\t" + op1 + "("
            source += ', '.join([t for t in push_tmp[::-1] if t])
            source += ");\n"
            push_tmp = []


        '''

        '''
        if "setz" == ins:
            reg_zero_check = 1
            if index_search(op1[:1],reg2) >= 0:
                reg_zero = op1[:1]
        '''

        '''
        if "movzx" == ins:
            if reg_zero_check == 1:
                if index_search(op1,reg) == index_search(reg_zero,reg2):
                    tmp[index_search(op1,reg)] = ''
            reg_zero_check = 0

        '''

        '''
        if "not" == ins:
            if index_search(op1,reg) >= 0:
                tmp[index_search(op1,reg)] = "~"+str(tmp[index_search(op1,reg)])
        '''

        '''
        if "or" == ins:
            if index_search(op1,reg) >= 0:
                if index_search(op2,reg) >= 0:
                    tmp[index_search(op1,reg)] = str(tmp[index_search(op1,reg)]) + "|" + str(tmp[index_search(op2,reg)])
    source += "\n}" 
    return source.replace('\'', '\"')

''' Main function for Custom Hexrays

Checking binary's architecture and Perform the corresponding function.

'''
def Main():
    FuncList = GetFuncList()
    print "[+] Start Hex-rays."
    file_type = get_file_type_name()
    path_ = idaapi.get_input_file_path()

    if file_type.find("x86-64") != -1:      # 64bit binary 
        f = open(path_ + '.c', 'wb')
        convert = lambda x : repr(x.strip('\'')) if '\\' in repr(x) else x
        # ====================================================
        f.write(HexRay64(FuncList[5]))  # need to modify
        f.write(HexRay64(FuncList[6]))  # need to modify, too
        # ====================================================
    elif file_type.find("Intel 386") != -1: # 32bit binary
        f = open(path_ + '.c', 'wb')
        # ====================================================
        f.write(HexRay32(FuncList[6]))
        # ====================================================

    f.close()
    print "[*] {}{}{}".format('-'*20, path_+'.c', '-'*20)
    print open(path_ + '.c', 'rb').read()
    print "[*] {}\n\n".format('-'*70)
    print "[*] Success Convering."

    '''
    try:
        if file_type.find("x86-64") != -1:      # 64bit binary 
            f = open(path_ + '.c', 'wb')
            convert = lambda x : repr(x.strip('\'')) if '\\' in repr(x) else x
            # ====================================================
            f.write(HexRay64(FuncList[5]))  # need to modify
            f.write(HexRay64(FuncList[6]))  # need to modify, too
            # ====================================================
        elif file_type.find("Intel 386") != -1: # 32bit binary
            f = open(path_ + '.c', 'wb')
            # ====================================================
            f.write(HexRay32(FuncList[6]))
            # ====================================================

        f.close()
        print "[*] {}{}{}".format('-'*20, path_+'.c', '-'*20)
        print open(path_ + '.c', 'rb').read()
        print "[*] {}\n\n".format('-'*70)
        print "[*] Success Convering."
    except:
        f.close()
        print "[-] Not supported."
    '''
if __name__ == '__main__':
    Main()
