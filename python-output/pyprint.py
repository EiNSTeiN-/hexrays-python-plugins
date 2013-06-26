""" Python printer for Hexrays Decompiler

Author: EiNSTeiN_ <einstein@g3nius.org>


Prints out the AST with a Python syntax instead of the normal C syntax.

* Pre/post increments or decrements are translated into "i += 1".
* For loops are translated in an equivalent while loop.
* Some names are translated, like strlen or printf, more should be added.
* Structures are printed out as classes.

Usage:
>>> pyprint(here()) # print current function
>>> pyprint(0x402010) # print function at specified address
"""

import idautils

translate_name = {
    '.strlen': 'len',
    '.printf': 'print',
    '.puts': 'print',
}

class printer(object):
    
    def __init__(self, cfunc, print_structures=True):
        
        self.cfunc = cfunc
        
        #~ self.structs = dict([(s[2], dict([(m[0], m[1]) for m in idautils.StructMembers(s[1])])) for s in idautils.Structs()])
        
        self.used_structs = []
        
        return
    
    def __str__(self):
        
        fct = s = '# Function: 0x%x\n' % (self.cfunc.entry_ea, )
        fct += self.do(self.cfunc)
        
        members = self.do_structs()
        
        return '%s\n\n%s' % (members, fct)
    
    def do_struct(self, name):
        s = ''
        
        sid = idc.GetStrucIdByName(name)
        
        s += 'class %s():\n' % (name, )
        s += '  def __init__(self):\n'
        for offset, name, size in idautils.StructMembers(sid):
            
            flags = idc.GetMemberFlag(sid, offset)
            if flags & idaapi.FF_STRU == idaapi.FF_STRU:
                msid = idc.GetMemberStrId(sid, offset)
                value = idc.GetStrucName(msid)
                if value not in self.used_structs:
                    self.used_structs.append(value)
            else:
                value = '0'
            s += '    self.%s = %s\n' % (name, value)
        s += '    return'
        
        return s
    
    def do_structs(self):
        
        s = ''
        
        for name in self.used_structs:
            s += self.do_struct(name)
        
        return s
    
    def do(self, obj):
        
        _indent = lambda s: '  ' + '\n  '.join(s.split('\n'))
        
        if type(obj) in (hexrays.cfuncptr_t, hexrays.cfunc_t):
            body = self.do(obj.body)[1:]
            
            prototype = 'def %s(%s):' % (self.make_name(self.cfunc.entry_ea), \
                    ', '.join([str(a.name) for a in self.cfunc.arguments]))
            
            vars = '\n'
            for lvar in obj.lvars:
                if lvar.is_arg_var:
                    continue
                if not lvar.used:
                    continue
                if lvar._type.is_struct:
                    #~ value = '%s()' % str(lvar._type)
                    vars += '  %s = %s()\n' % (lvar.name, str(lvar._type))
                else:
                    vars += '  # %s %s\n' % (str(lvar._type), lvar.name, )
            
            s = prototype + vars + body
        elif type(obj) == hexrays.cinsn_t:
            
            if obj.op == hexrays.cit_continue:
                return 'continue'
            elif obj.op == hexrays.cit_break:
                return 'break'
            
            s = self.do(obj.details)
            
        elif type(obj) == hexrays.cblock_t:
            
            lines = []
            for stmt in obj:
                lines.append(_indent(self.do(stmt)))
            
            s = ':\n%s' % ('\n'.join(lines), )
            
        elif type(obj) == hexrays.cif_t:
            
            cond = self.do(obj.expr)
            ithen = self.do(obj.ithen)
            if obj.ielse:
                ielse = self.do(obj.ielse)
            else:
                ielse = None
            
            s = 'if (%s)%s' % (cond, ithen, )
            if ielse:
                s += '\nelse%s' % (ielse, )
            
        elif type(obj) == hexrays.cfor_t:
            
            init = self.do(obj.init)
            body = self.do(obj.body)
            step = self.do(obj.step)
            
            if obj.expr.op == hexrays.cot_empty:
                cond = 'True'
            else:
                cond = self.do(obj.expr)
            
            s = '%s\nwhile (%s)%s\n%s' % (init, cond, body, _indent(step))
            
        elif type(obj) == hexrays.cwhile_t:
            
            cond = self.do(obj.expr)
            body = self.do(obj.body)
            
            s = 'while (%s)%s' % (cond, body, )
            
        elif type(obj) == hexrays.cdo_t:
            
            cond = self.do(obj.expr)
            body = self.do(obj.body)
            
            s = 'while True%s\n  if not (%s):\n    break' % (body, cond)
        
        elif type(obj) == hexrays.creturn_t:
            
            s = 'return %s' % (self.do(obj.expr), )
        
        #~ elif type(obj) == hexrays.cswitch_t:
            
        #~ elif type(obj) == hexrays.cgoto_t:
            
        #~ elif type(obj) == hexrays.casm_t:
            
        elif type(obj) in (hexrays.cexpr_t, hexrays.carg_t):
            
            format = {
                hexrays.cot_comma:    '{x}, {y}',
                hexrays.cot_asg:      '{x} = {y}',
                hexrays.cot_asgbor:   '{x} |= {y}',
                hexrays.cot_asgxor:   '{x} ^= {y}',
                hexrays.cot_asgband:  '{x} &= {y}',
                hexrays.cot_asgadd:   '{x} += {y}',
                hexrays.cot_asgsub:   '{x} -= {y}',
                hexrays.cot_asgmul:   '{x} *= {y}',
                hexrays.cot_asgsshr:  '{x} >>= {y}',
                hexrays.cot_asgushr:  '{x} >>= {y}',
                hexrays.cot_asgshl:   '{x} <<= {y}',
                hexrays.cot_asgsdiv:  '{x} /= {y}',
                hexrays.cot_asgudiv:  '{x} /= {y}',
                hexrays.cot_asgsmod:  '{x} %= {y}',
                hexrays.cot_asgumod:  '{x} %= {y}',
                hexrays.cot_tern:     '{x} ? {y} : {z}',
                hexrays.cot_lor:      '{x} || {y}',
                hexrays.cot_land:     '{x} && {y}',
                hexrays.cot_bor:      '{x} | {y}',
                hexrays.cot_xor:      '{x} ^ {y}',
                hexrays.cot_band:     '{x} & {y}',
                hexrays.cot_eq:       '{x} == {y}',
                hexrays.cot_ne:       '{x} != {y}',
                hexrays.cot_sge:      '{x} >= {y}',
                hexrays.cot_uge:      '{x} >= {y}',
                hexrays.cot_sle:      '{x} <= {y}',
                hexrays.cot_ule:      '{x} <= {y}',
                hexrays.cot_sgt:      '{x} >  {y}',
                hexrays.cot_ugt:      '{x} >  {y}',
                hexrays.cot_slt:      '{x} <  {y}',
                hexrays.cot_ult:      '{x} <  {y}',
                hexrays.cot_sshr:     '{x} >> {y}',
                hexrays.cot_ushr:     '{x} >> {y}',
                hexrays.cot_shl:      '{x} << {y}',
                hexrays.cot_add:      '{x} + {y}',
                hexrays.cot_sub:      '{x} - {y}',
                hexrays.cot_mul:      '{x} * {y}',
                hexrays.cot_sdiv:     '{x} / {y}',
                hexrays.cot_udiv:     '{x} / {y}',
                hexrays.cot_smod:     '{x} % {y}',
                hexrays.cot_umod:     '{x} % {y}',
                hexrays.cot_fadd:     '{x} + {y}',
                hexrays.cot_fsub:     '{x} - {y}',
                hexrays.cot_fmul:     '{x} * {y}',
                hexrays.cot_fdiv:     '{x} / {y}',
                hexrays.cot_fneg:     '-{x}',
                hexrays.cot_neg:      '-{x}',
                hexrays.cot_lnot:     '!{x}',
                hexrays.cot_bnot:     '~{x}',
                hexrays.cot_ptr:      '*{x}',
                hexrays.cot_ref:      '&{x}',
                hexrays.cot_postinc:  '{x} += 1',
                hexrays.cot_postdec:  '{x} -= 1',
                hexrays.cot_preinc:   '{x} += 1',
                hexrays.cot_predec:   '{x} -= 1',
                hexrays.cot_call:     '{x}({a})',
                hexrays.cot_idx:      '{x}[{y}]',
                hexrays.cot_num:      '{n}',
                hexrays.cot_fnum:     '{fpc}',
                hexrays.cot_str:      '{string}',
                hexrays.cot_var:      '{v}',
                hexrays.cot_sizeof:   'sizeof({x})',
                hexrays.cot_helper:   '{helper}',
                hexrays.cot_cast:     '{x}',
            }
            
            #~ hexrays.cot_memref:   '{x}.{m}',
            #~ hexrays.cot_memptr:   '{x}->{m}',
            #~ hexrays.cot_obj:      '{obj_ea}',
            
            if obj.op in format:
                
                operands = obj.operands
                for name in operands:
                    
                    if type(operands[name]) == hexrays.cnumber_t:
                        
                        operands[name] = operands[name].value(obj.type)
                        
                    else:
                        operands[name] = self.do(operands[name])
                s = format[obj.op].format(**operands)
                
            elif obj.op == hexrays.cot_obj:
                
                s = self.make_name(obj.obj_ea)
                
            elif obj.op in (hexrays.cot_memptr, hexrays.cot_memref):
                
                x = obj.operands['x']
                m = obj.operands['m']
                
                xtype = typestring(x.type.u_str())
                xtype.remove_ptr_or_array()
                typename = str(xtype)
                
                sid = idc.GetStrucIdByName(str(xtype))
                if not sid:
                    print 'error getting structure %s' % (repr(typename), )
                    member = 'field_%x' % (m, )
                else:
                    member = idc.GetMemberName(sid, m)
                    if not member:
                        member = 'field_%x' % (m, )
                    else:
                        if typename not in self.used_structs:
                            self.used_structs.append(typename)
                
                name = self.do(x)
                
                s = '{x}.{m}'.format(x=name, m=member)
                
            elif obj.op == hexrays.cot_empty:
                s = ''
            else:
                s = '<%s>' % (repr(obj.opname), )
        
        elif type(obj) == hexrays.var_ref_t:
            
            s = self.cfunc.lvars[obj.idx].name
        
        elif type(obj) == hexrays.typestring:
            
            s = str(obj)
        
        elif type(obj) == hexrays.carglist_t:
            
            s = ', '.join([self.do(v) for v in obj])
        
        else:
            
            print 'I do not know how to print object type %s' % (obj.__class__.__name__, )
            return ''
        
        return s
    
    def make_name(self, ea):
        
        
        if idaapi.get_func(ea) is None:
            
            try:
                s = idc.GetString(ea)
                if s:
                    return repr(s)
            except:
                pass
        
        names = dict(idautils.Names())
        
        name = names.get(ea)
        if name:
            if name in translate_name:
                name = translate_name[name]
        else:
            name = 'loc_%x' % (ea, )
        
        return name

def pyprint(ea):
    
    c = decompile(ea)
    c.refcnt += 1

    p = printer(c)
    s = str(p)
    
    return s


